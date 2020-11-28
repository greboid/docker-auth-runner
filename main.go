package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/cesanta/docker_auth/auth_server/server"
	logger "github.com/greboid/go-log"
	"github.com/kouhin/envflag"
	"gopkg.in/yaml.v3"
)

var (
	emptyString          = ""
	pullString           = "pull"
	publicWildcard       = "public/*"
	publicDoubleWildcard = "public/*/*"
	mirrorWildcard       = "mirror/*"
	mirrorDoubleWildcard = "mirror/*/*"
	certsDir             = flag.String("certs-dir", "/certs", "Specifies the certificates directory")
	configDir            = flag.String("config-dir", "/app", "Specifies the config directory")
	appDir               = flag.String("app-dir", "/app", "Specifies the application directory")
	listenAddress        = flag.Int("registry-listen-address", 5001, "Specifies the auth server listen address")
	issuer               = flag.String("registry-issuer", "Private registry", "Specifies the auth server listen address")
	mirror               = flag.Bool("registry-mirror-folder", false, "Should there be a public /mirror folder")
	public               = flag.Bool("registry-public-folder", false, "Should there be a public /public folder")
)

type User struct {
	Username string
	Password api.PasswordString
}

func main() {
	if err := envflag.Parse(); err != nil {
		fmt.Printf("Unable to load config: %s", err.Error())
		return
	}
	log, err := logger.CreateLogger(false)
	if err != nil {
		fmt.Printf("Unable to load logger")
		return
	}
	log.Infof("Starting config generator")
	authServer := *appDir + "auth_server"
	if runtime.GOOS == "windows" {
		authServer = *appDir + "auth_server.exe"
	}
	_, err = os.Stat(authServer)
	if os.IsNotExist(err) {
		log.Fatalf(authServer + " must exist")
	}
	_, err = os.Stat(*certsDir + "/server.pem")
	if os.IsNotExist(err) {
		log.Fatalf(*certsDir + "/server.pem must exist")
	}
	_, err = os.Stat(*certsDir + "/key.pem")
	if os.IsNotExist(err) {
		log.Fatalf(*certsDir + "/key.pem must exist")
	}
	users := parseUsersFromEnvironment()
	config := server.Config{
		Server: server.ServerConfig{
			ListenAddress: fmt.Sprintf(":%d", *listenAddress),
		},
		Token: server.TokenConfig{
			Issuer:     *issuer,
			Expiration: 900,
			CertFile:   *certsDir + "server.pem",
			KeyFile:    *certsDir + "key.pem",
		},
		Users: getUsers(users),
		ACL:   getACL(users),
	}
	bytes, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatalf("Unable to create config: %s", err.Error())
		return
	}
	configFile, err := os.Create(*configDir + "/config.yml")
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
	cmnd := exec.Command(authServer, *configDir+"/config.yml")
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
	if *mirror {
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
	if *public {
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
