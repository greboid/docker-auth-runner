package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/cesanta/docker_auth/auth_server/server"
	logger "github.com/greboid/go-log"
	"gopkg.in/yaml.v3"
)

var (
	emptyString          = ""
	pullString           = "pull"
	publicWildcard       = "public/*"
	publicDoubleWildcard = "public/*/*"
	mirrorWildcard       = "mirror/*"
	mirrorDoubleWildcard = "mirror/*/*"
	publicMirror         = false
	publicFolder         = false
)

type User struct {
	Username string
	Password api.PasswordString
}

func main() {
	log, err := logger.CreateLogger(false)
	if err != nil {
		fmt.Printf("Unable to load logger")
		return
	}
	log.Infof("Starting config generator")
	addr := os.Getenv("REGISTRY_LISTEN_ADDRESS")
	if len(addr) == 0 {
		log.Fatalf("REGISTRY_LISTEN_ADDRESS is required")
		return
	}
	issuer := os.Getenv("REGISTRY_ISSUER")
	if len(issuer) == 0 {
		log.Fatalf("REGISTRY_ISSUER is required")
		return
	}
	_, err = os.Stat("/certs/server.pem")
	if os.IsNotExist(err) {
		log.Fatalf("/certs/server.pem must exist")
	}
	_, err = os.Stat("/certs/key.pem")
	if os.IsNotExist(err) {
		log.Fatalf("/certs/key.pem must exist")
	}
	publicMirrorString := os.Getenv("REGISTRY_PUBLIC_MIRROR")
	if len(publicMirrorString) != 0 {
		if strings.ToLower(publicMirrorString) == "true" {
			log.Infof("Enabling public mirror folder")
			publicMirror = true
		}
	}
	publicFolderString := os.Getenv("REGISTRY_PUBLIC_FOLDER")
	if len(publicFolderString) != 0 {
		if strings.ToLower(publicFolderString) == "true" {
			log.Infof("Enabling public folder")
			publicFolder = true
		}
	}
	users := parseUsersFromEnvironment()
	config := server.Config{
		Server: server.ServerConfig{
			ListenAddress: addr,
		},
		Token: server.TokenConfig{
			Issuer:     issuer,
			Expiration: 900,
			CertFile:   "/certs/server.pem",
			KeyFile:    "/certs/key.pem",
		},
		Users: getUsers(users),
		ACL:   getACL(users),
	}
	bytes, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatalf("Unable to create config: %s", err.Error())
		return
	}
	configFile, err := os.Create("config.yml")
	if err != nil {
		log.Fatalf("Unable to create config file: %s", err.Error())
		return
	}
	defer func() {
		_ = configFile.Close()
	}()
	_, err = configFile.Write(bytes)
	if err != nil {
		log.Fatalf("Unable to write to config file: %s", err.Error())
		return
	}
	log.Infof("Config file written")
	log.Infof("Executing auth_server")
	cmnd := exec.Command("./auth_server", "/app/config.yml")
	cmnd.Stdout = os.Stdout
	cmnd.Stderr = os.Stderr
	err = cmnd.Run()
	if err, k := err.(*exec.ExitError); k {
		log.Fatalf("Unable to start auth_server: %s", err.Error())
	}
	log.Infof("Exiting auth_server")
}

func getUsers(users []User) map[string]*authn.Requirements {
	requirements := make(map[string]*authn.Requirements, 0)
	for index := range users {
		requirements[users[index].Username] = &authn.Requirements{
			Password: &users[index].Password,
		}
	}
	requirements[emptyString] = &authn.Requirements{}
	return requirements
}

func getACL(users []User) authz.ACL {
	acl := make(authz.ACL, 0)
	for index := range users {
		acl = append(acl, authz.ACLEntry{
			Match: &authz.MatchConditions{
				Account: &users[index].Username,
			},
			Actions: &[]string{"*"},
			Comment: &users[index].Username,
		})
	}
	if publicMirror {
		acl = append(acl, authz.ACLEntry{
			Match: &authz.MatchConditions{
				Account: &emptyString,
				Name:    &mirrorWildcard,
			},
			Actions: &[]string{pullString},
			Comment: &pullString,
		})
		acl = append(acl, authz.ACLEntry{
			Match: &authz.MatchConditions{
				Account: &emptyString,
				Name:    &mirrorDoubleWildcard,
			},
			Actions: &[]string{pullString},
			Comment: &pullString,
		})
	}
	if publicFolder {
		acl = append(acl, authz.ACLEntry{
			Match: &authz.MatchConditions{
				Account: &emptyString,
				Name:    &publicWildcard,
			},
			Actions: &[]string{pullString},
			Comment: &pullString,
		})
		acl = append(acl, authz.ACLEntry{
			Match: &authz.MatchConditions{
				Account: &emptyString,
				Name:    &publicDoubleWildcard,
			},
			Actions: &[]string{pullString},
			Comment: &pullString,
		})
	}
	return acl
}

func parseUsersFromEnvironment() []User {
	envVars := os.Environ()
	users := make([]User, 0)
	for _, env := range envVars {
		if !strings.HasPrefix(env, "REGISTRY_USER_") {
			continue
		}
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			parts := strings.SplitN(parts[1], ":", 2)
			if len(parts) == 2 {
				users = append(users, User{parts[0], api.PasswordString(parts[1])})
			}
		}
	}
	return users
}
