// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh

import (
	"context"
	"net"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/observability/tracing"
)

const (
	// EnvsRequest sets multiple environment variables that will be applied to any
	// command executed by Shell or Run.
	// See [EnvsReq] for the corresponding payload.
	EnvsRequest = "envs@goteleport.com"

	// instrumentationName is the name of this instrumentation package.
	instrumentationName = "otelssh"
)

// EnvsReq contains json marshaled key:value pairs sent as the
// payload for an [EnvsRequest].
type EnvsReq struct {
	// EnvsJSON is a json marshaled map[string]string containing
	// environment variables.
	EnvsJSON []byte `json:"envs"`
}

// FileTransferReq contains parameters used to create a file transfer
// request to be stored in the SSH server
type FileTransferReq struct {
	// Download is true if the file transfer requests a download, false if upload
	Download bool
	// Location is the location of the file to be downloaded, or directory to upload a file
	Location string
	// Filename is the name of the file to be uploaded
	Filename string
}

// FileTransferDecisionReq contains parameters used to approve or deny an active
// file transfer request on the SSH server
type FileTransferDecisionReq struct {
	// RequestID is the ID of the file transfer request being responded to
	RequestID string
	// Approved is true if approved, false if denied.
	Approved bool
}

// Dial starts a client connection to the given SSH server. It is a
// convenience function that connects to the given network address,
// initiates the SSH handshake, and then sets up a Client.  For access
// to incoming channels and requests, use net.Dial with NewClientConn
// instead.
func Dial(ctx context.Context, network, addr string, config *ssh.ClientConfig, opts ...tracing.Option) (*Client, error) {
	dialer := net.Dialer{Timeout: config.Timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := NewClientConn(ctx, conn, addr, config, opts...)
	if err != nil {
		return nil, err
	}
	return NewClient(c, chans, reqs), nil
}

// NewClientConn creates a new SSH client connection that is passed tracing context so that spans may be correlated
// properly over the ssh connection.
func NewClientConn(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig, opts ...tracing.Option) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	return c, chans, reqs, nil
}

// NewClientConnWithDeadline establishes new client connection with specified deadline
func NewClientConnWithDeadline(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig, opts ...tracing.Option) (*Client, error) {
	if config.Timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(config.Timeout)); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	c, chans, reqs, err := NewClientConn(ctx, conn, addr, config, opts...)
	if err != nil {
		return nil, err
	}
	if config.Timeout > 0 {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return NewClient(c, chans, reqs, opts...), nil
}
