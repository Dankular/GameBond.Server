package adminportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Dankular/GameBond.Server/adminauth"
)

func (p *Portal) teamUsers(team string) []map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.teamUsersLocked(team)
}

func (p *Portal) teamUsersLocked(team string) []map[string]string {
	users := p.o.Settings.Users
	if len(users) == 0 && p.passwordHash != "" {
		users = []AdminUser{{Username: "admin", Team: "default", Role: "system-admin", PasswordHash: p.passwordHash}}
	}
	out := make([]map[string]string, 0)
	for _, user := range users {
		if user.Team == team {
			out = append(out, map[string]string{"username": user.Username, "team": user.Team, "role": user.Role})
		}
	}
	return out
}

// changeTeamUser modifies only identities belonging to the caller's team.
// User hashes and the admin.users array are persisted in the protected config.
func (p *Portal) changeTeamUser(team, action, username, current, password, role string) ([]map[string]string, error) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return nil, errors.New("username must be 1..64 letters, digits, dot, underscore, or hyphen")
	}
	var passwordHash string
	if action == "create" {
		if role != "editor" && role != "viewer" && role != "team-admin" {
			return nil, errors.New("new team users must have editor, viewer, or team-admin role")
		}
	}
	if action == "create" || action == "password" {
		if !p.acquireHash() {
			return nil, errors.New("server is busy hashing passwords; try again shortly")
		}
		if action == "password" {
			p.mu.Lock()
			existingHash := ""
			for _, user := range p.o.Settings.Users {
				if user.Team == team && strings.EqualFold(user.Username, username) {
					existingHash = user.PasswordHash
					break
				}
			}
			p.mu.Unlock()
			if existingHash == "" || !adminauth.VerifyPassword(current, existingHash) {
				p.releaseHash()
				return nil, errors.New("current password is wrong")
			}
		}
		var err error
		passwordHash, err = adminauth.HashPassword(password, adminauth.ScryptN)
		p.releaseHash()
		if err != nil {
			return nil, err
		}
	} else if action != "delete" {
		return nil, errors.New("user action must be create, password, or delete")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	previous, err := p.ReadConfig()
	if err != nil {
		return nil, err
	}
	doc, err := parseOrdered(previous)
	if err != nil || doc.kind != 'o' {
		return nil, errors.New("configuration is not a JSON object")
	}
	admin := doc.get("admin")
	if admin == nil {
		return nil, errors.New("admin settings are missing")
	}
	if admin.kind != 'o' {
		return nil, errors.New("admin settings are invalid")
	}
	users := append([]AdminUser(nil), p.o.Settings.Users...)
	if len(users) == 0 && p.passwordHash != "" {
		users = append(users, AdminUser{Username: "admin", Team: "default", Role: "system-admin", PasswordHash: p.passwordHash})
	}
	found := -1
	for i, user := range users {
		if strings.EqualFold(user.Username, username) {
			found = i
			break
		}
	}
	switch action {
	case "create":
		if found >= 0 {
			return nil, errors.New("username already exists")
		}
		users = append(users, AdminUser{Username: username, Team: team, Role: role, PasswordHash: passwordHash})
	case "delete":
		if found < 0 || users[found].Team != team {
			return nil, errors.New("team user was not found")
		}
		if users[found].Role == "admin" || users[found].Role == "team-admin" || users[found].Role == "system-admin" {
			return nil, errors.New("admin accounts can only be changed in the protected configuration")
		}
		users = append(users[:found], users[found+1:]...)
	case "password":
		if found < 0 || users[found].Team != team {
			return nil, errors.New("account was not found")
		}
		users[found].PasswordHash = passwordHash
	}
	encoded, err := json.Marshal(users)
	if err != nil {
		return nil, err
	}
	userNode, err := parseOrdered(string(encoded))
	if err != nil {
		return nil, err
	}
	admin.set("users", userNode)
	var next bytes.Buffer
	doc.encode(&next, 0)
	updated := next.Bytes()
	newSettings, err := ParseSettings(json.RawMessage(adminJSON(admin)))
	if err != nil {
		return nil, fmt.Errorf("updated admin users are invalid: %w", err)
	}
	if err := writeInPlace(p.o.ConfigPath, updated); err != nil {
		p.restoreConfig(previous)
		return nil, err
	}
	if actual, err := os.ReadFile(p.o.ConfigPath); err != nil || string(actual) != string(updated) {
		p.restoreConfig(previous)
		return nil, errors.New("user configuration was not written correctly; previous configuration restored")
	}
	p.o.Settings.Users = newSettings.Users
	if action == "delete" {
		p.Sessions.DropUser(team, username)
	}
	p.Note("team user " + username + " " + action + "d in " + team)
	return p.teamUsersLocked(team), nil
}

func adminJSON(n *node) string {
	var out bytes.Buffer
	n.encode(&out, 0)
	return string(out.Bytes())
}
