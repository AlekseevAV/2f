package keychainUtils

import (
	"errors"
	"log"
	"os/exec"
	"strings"
)

var MainCommand = "security"

type KeyChain struct {
	Path string
	Name string
	Keys map[string]Key
}

type Key struct {
	Service     string
	Account     string
	Description string
	Password    string
}

func runSecurityCommand(args ...string) string {
	cmd := exec.Command(MainCommand, args...)
	stdout, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	return strings.Trim(string(stdout), "\n ")
}

func KeychainsList() []KeyChain {
	output := runSecurityCommand("list-keychains")
	var keychains []KeyChain
	splittedOutput := strings.Split(output, "\n")
	for i := range splittedOutput {
		keychainPath := strings.Trim(splittedOutput[i], " \"")
		keychainPathElements := strings.Split(keychainPath, "/")
		keychains = append(keychains, KeyChain{
			Path: keychainPath,
			Name: strings.Trim(keychainPathElements[len(keychainPathElements)-1], "-db"),
		})
	}

	return keychains
}

func addKeyChainToSearchList(name string) {
	commandParams := []string{"list-keychains", "-d", "user", "-s", name}
	existKeyChains := KeychainsList()
	for i := range existKeyChains {
		keychain := existKeyChains[i]
		commandParams = append(commandParams, keychain.Name)
	}
	runSecurityCommand(commandParams...)
}

func CreateKeyChain(name string, password string) {
	runSecurityCommand("create-keychain", "-p", password, name)
	addKeyChainToSearchList(name)
}

func AddPassword(account string, service string, password string, kind string, keychain string) {
	runSecurityCommand("add-generic-password", "-a", account, "-s", service, "-w", password, "-D", kind, keychain)
}

func DeletePassword(service string, keychain string) {
	runSecurityCommand("delete-generic-password", "-s", service, keychain)
}

func GetPassword(service string, keychain string) string {
	output := runSecurityCommand("find-generic-password", "-w", "-s", service, keychain)
	return output
}

func GetKeyChain(name string) (KeyChain, error) {
	keychains := KeychainsList()
	for i := range keychains {
		keychain := keychains[i]
		if keychain.Name == name {
			return keychain, nil
		}
	}

	return KeyChain{}, errors.New("cannot find keychain: " + name)
}

func parseKeyData(rawKeyData string) Key {
	dataLines := strings.Split(rawKeyData, "\n")
	key := Key{}
	for i := range dataLines {
		line := dataLines[i]
		if strings.HasPrefix(line, "    \"acct\"<blob>=\"") {
			key.Account = strings.Trim(line[17:], "\"")
		} else if strings.HasPrefix(line, "    \"svce\"<blob>=\"") {
			key.Service = strings.Trim(line[17:], "\"")
		} else if strings.HasPrefix(line, "    \"desc\"<blob>=\"") {
			key.Description = strings.Trim(line[17:], "\"")
		}
	}
	return key
}

func GetKeyChainEntities(name string) []Key {
	output := runSecurityCommand("dump-keychain", "-d", name)
	var keys []Key
	keychainsData := strings.Split(output, "keychain: \"")
	for i := range keychainsData {
		keyData := keychainsData[i]
		if keyData != "" {
			keys = append(keys, parseKeyData(keyData))
		}
	}
	return keys
}
