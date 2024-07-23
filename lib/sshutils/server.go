/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Package sshutils contains the implementations of the base SSH
// server used throughout Teleport.
package sshutils



const (
	// SSHVersionPrefix is the prefix of "server version" string which begins
	// every SSH handshake. It MUST start with "SSH-2.0" according to
	// https://tools.ietf.org/html/rfc4253#page-4
	SSHVersionPrefix = "SSH-2.0-Teleport"

	// MaxVersionStringBytes is the maximum number of bytes allowed for a
	// SSH version string
	// https://tools.ietf.org/html/rfc4253
	MaxVersionStringBytes = 255
)

// SSHServerVersionOverrider returns a SSH server version string that should be
// used instead of the one from a static configuration (typically because the
// version was already sent and can't be un-sent). If SSHServerVersionOverride
// returns a blank string (which is an invalid version string, as version
// strings should start with "SSH-2.0-") then no override is specified. The
// string is intended to be passed as the [ssh.ServerConfig.ServerVersion], so
// it should not include a trailing CRLF pair ("\r\n").
type SSHServerVersionOverrider interface {
       SSHServerVersionOverride() string
}
