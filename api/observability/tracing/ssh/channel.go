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

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/observability/tracing"
)

// Channel is a wrapper around ssh.Channel that adds tracing support.
type Channel struct {
	ssh.Channel
	tracingSupported tracingCapability
	opts             []tracing.Option
}

// NewTraceChannel creates a new Channel.
func NewTraceChannel(ch ssh.Channel, opts ...tracing.Option) *Channel {
	return &Channel{
		Channel: ch,
		opts:    opts,
	}
}

// SendRequest sends a global request, and returns the
// reply. If tracing is enabled, the provided payload
// is wrapped in an Envelope to forward any tracing context.
func (c *Channel) SendRequest(ctx context.Context, name string, wantReply bool, payload []byte) (_ bool, err error) {
	return c.Channel.SendRequest(
		name, wantReply, payload,
	)
}

