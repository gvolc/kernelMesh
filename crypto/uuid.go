// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package crypto

import (
	"github.com/google/uuid"
)

func NewUUID() string {
	return uuid.New().String()
}
