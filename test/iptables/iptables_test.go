// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/dockerutil"
	"gvisor.dev/gvisor/runsc/testutil"
)

const timeout = 18 * time.Second

var image = flag.String("image", "bazel/test/iptables/runner:runner-image", "image to run tests in")

type result struct {
	output string
	err    error
}

// singleTest runs a TestCase. Each test follows a pattern:
// - Create a container.
// - Get the container's IP.
// - Send the container our IP.
// - Start a new goroutine running the local action of the test.
// - Wait for both the container and local actions to finish.
//
// Container output is logged to $TEST_UNDECLARED_OUTPUTS_DIR if it exists, or
// to stderr.
func singleTest(test TestCase, lConn *net.TCPListener) error {
	if _, ok := Tests[test.Name()]; !ok {
		return fmt.Errorf("no test found with name %q. Has it been registered?", test.Name())
	}

	// Create and start the container.
	cont := dockerutil.MakeDocker("gvisor-iptables")
	defer cont.CleanUp()
	resultChan := make(chan *result)
	go func() {
		var port int
		if lConn != nil {
			addr := lConn.Addr()
			port = addr.(*net.TCPAddr).Port
		}
		output, err := cont.RunFg("--cap-add=NET_ADMIN", *image, "-name", test.Name(), "-port", fmt.Sprintf("%d", port))
		logContainer(output, err)
		resultChan <- &result{output, err}
	}()

	// Get the container IP.
	ip, err := getIP(cont)
	if err != nil {
		return fmt.Errorf("failed to get container IP: %v", err)
	}

	// Give the container our IP.
	if err := sendIP(ip); err != nil {
		return fmt.Errorf("failed to send IP to container: %v", err)
	}

	// Run our side of the test.
	errChan := make(chan error)
	go func() {
		errChan <- test.LocalAction(ip, lConn)
	}()

	// Wait for both the container and local tests to finish.
	var res *result
	to := time.After(timeout)
	for localDone := false; res == nil || !localDone; {
		select {
		case res = <-resultChan:
			log.Infof("Container finished.")
		case err, localDone = <-errChan:
			log.Infof("Local finished.")
			if err != nil {
				return fmt.Errorf("local test failed: %v", err)
			}
		case <-to:
			return fmt.Errorf("timed out after %f seconds", timeout.Seconds())
		}
	}

	return res.err
}

func getIP(cont dockerutil.Docker) (net.IP, error) {
	// The container might not have started yet, so retry a few times.
	var ipStr string
	to := time.After(timeout)
	for ipStr == "" {
		ipStr, _ = cont.FindIP()
		select {
		case <-to:
			return net.IP{}, fmt.Errorf("timed out getting IP after %f seconds", timeout.Seconds())
		default:
			time.Sleep(250 * time.Millisecond)
		}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return net.IP{}, fmt.Errorf("invalid IP: %q", ipStr)
	}
	log.Infof("Container has IP of %s", ipStr)
	return ip, nil
}

func sendIP(ip net.IP) error {
	contAddr := net.TCPAddr{
		IP:   ip,
		Port: IPExchangePort,
	}
	var conn *net.TCPConn
	// The container may not be listening when we first connect, so retry
	// upon error.
	cb := func() error {
		c, err := net.DialTCP("tcp4", nil, &contAddr)
		conn = c
		return err
	}
	if err := testutil.Poll(cb, timeout); err != nil {
		return fmt.Errorf("timed out waiting to send IP, most recent error: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("error writing to container: %v", err)
	}
	return nil
}

func logContainer(output string, err error) {
	msg := fmt.Sprintf("Container error: %v\nContainer output:\n%v", err, output)
	if artifactsDir := os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"); artifactsDir != "" {
		fpath := path.Join(artifactsDir, "container.log")
		if file, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE, 0644); err != nil {
			log.Warningf("Failed to open log file %q: %v", fpath, err)
		} else {
			defer file.Close()
			if _, err := file.Write([]byte(msg)); err == nil {
				return
			}
			log.Warningf("Failed to write to log file %s: %v", fpath, err)
		}
	}

	// We couldn't write to the output directory -- just log to stderr.
	log.Infof(msg)
}

func TestFilterInputDropUDP(t *testing.T) {
	if err := singleTest(FilterInputDropUDP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDropUDPPort(t *testing.T) {
	if err := singleTest(FilterInputDropUDPPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDropDifferentUDPPort(t *testing.T) {
	if err := singleTest(FilterInputDropDifferentUDPPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDropAll(t *testing.T) {
	if err := singleTest(FilterInputDropAll{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDropOnlyUDP(t *testing.T) {
	if err := singleTest(FilterInputDropOnlyUDP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATPreRedirectUDPPort(t *testing.T) {
	if err := singleTest(NATPreRedirectUDPPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATPreRedirectTCPPort(t *testing.T) {
	if err := singleTest(NATPreRedirectTCPPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATOutRedirectUDPPort(t *testing.T) {
	if err := singleTest(NATOutRedirectUDPPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATOutRedirectTCPPort(t *testing.T) {
	var localAddr net.TCPAddr

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer lConn.Close()

	// Accept connections on port.
	lConn.SetDeadline(time.Now().Add(timeout * 2))
	if err := singleTest(NATOutRedirectTCPPort{}, lConn); err != nil {
		t.Fatal(err)
	}
}

func TestNATDropUDP(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATDropUDP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATAcceptAll(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATAcceptAll{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDropTCPDestPort(t *testing.T) {
	if err := singleTest(FilterInputDropTCPDestPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDropTCPSrcPort(t *testing.T) {
	if err := singleTest(FilterInputDropTCPSrcPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputCreateUserChain(t *testing.T) {
	if err := singleTest(FilterInputCreateUserChain{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDefaultPolicyAccept(t *testing.T) {
	if err := singleTest(FilterInputDefaultPolicyAccept{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputDefaultPolicyDrop(t *testing.T) {
	if err := singleTest(FilterInputDefaultPolicyDrop{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterInputReturnUnderflow(t *testing.T) {
	if err := singleTest(FilterInputReturnUnderflow{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputDropTCPDestPort(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("filter OUTPUT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(FilterOutputDropTCPDestPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputDropTCPSrcPort(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("filter OUTPUT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(FilterOutputDropTCPSrcPort{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputAcceptTCPOwner(t *testing.T) {
	if err := singleTest(FilterOutputAcceptTCPOwner{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputDropTCPOwner(t *testing.T) {
	if err := singleTest(FilterOutputDropTCPOwner{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputAcceptUDPOwner(t *testing.T) {
	if err := singleTest(FilterOutputAcceptUDPOwner{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputDropUDPOwner(t *testing.T) {
	if err := singleTest(FilterOutputDropUDPOwner{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilterOutputOwnerFail(t *testing.T) {
	if err := singleTest(FilterOutputOwnerFail{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJumpSerialize(t *testing.T) {
	if err := singleTest(FilterInputSerializeJump{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJumpBasic(t *testing.T) {
	if err := singleTest(FilterInputJumpBasic{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJumpReturn(t *testing.T) {
	if err := singleTest(FilterInputJumpReturn{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJumpReturnDrop(t *testing.T) {
	if err := singleTest(FilterInputJumpReturnDrop{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJumpBuiltin(t *testing.T) {
	if err := singleTest(FilterInputJumpBuiltin{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJumpTwice(t *testing.T) {
	if err := singleTest(FilterInputJumpTwice{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInputDestination(t *testing.T) {
	if err := singleTest(FilterInputDestination{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInputInvertDestination(t *testing.T) {
	if err := singleTest(FilterInputInvertDestination{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOutputDestination(t *testing.T) {
	if err := singleTest(FilterOutputDestination{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOutputInvertDestination(t *testing.T) {
	if err := singleTest(FilterOutputInvertDestination{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATOutRedirectIP(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATOutRedirectIP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATOutDontRedirectIP(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATOutDontRedirectIP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATOutRedirectInvert(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATOutRedirectInvert{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATPreRedirectIP(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATPreRedirectIP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATPreDontRedirectIP(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATPreDontRedirectIP{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATPreRedirectInvert(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATPreRedirectInvert{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNATRedirectRequiresProtocol(t *testing.T) {
	// TODO(gvisor.dev/issue/170): Enable when supported.
	t.Skip("NAT isn't supported yet (gvisor.dev/issue/170).")
	if err := singleTest(NATRedirectRequiresProtocol{}, nil); err != nil {
		t.Fatal(err)
	}
}
