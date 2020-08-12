package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/AlekseevAV/2f/keychainUtils"
)

var defaultKeyChainName = "2f.keychain"

var (
	flagAdd    = flag.Bool("add", false, "add a key")
	flagDelete = flag.Bool("delete", false, "delete a key")
	flagList   = flag.Bool("list", false, "list keys")
	flag7      = flag.Bool("7", false, "generate 7-digit code")
	flag8      = flag.Bool("8", false, "generate 8-digit code")
)

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "usage:\n")
	_, _ = fmt.Fprintf(os.Stderr, "\t2f -add [-7] [-8] keyname\n")
	_, _ = fmt.Fprintf(os.Stderr, "\t2f -delete keyname\n")
	_, _ = fmt.Fprintf(os.Stderr, "\t2f -list\n")
	_, _ = fmt.Fprintf(os.Stderr, "\t2f keyname\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("2f: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	k := readKeychain(defaultKeyChainName)

	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if flag.NArg() == 0 && !*flagAdd {
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("name must not contain spaces")
	}
	if *flagAdd {
		k.add(name)
		return
	}
	if *flagDelete {
		k.delete(name)
		return
	}
	k.show(name)
}

type Keychain struct {
	name string
	keys map[string]Key
}

type Key struct {
	service  string
	account  string
	digits   int
	password string
}

func createKeychain(name string) keychainUtils.KeyChain {
	_, _ = fmt.Fprintf(os.Stderr, "2f password for new keychain: ")
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error creating keychain: %v", err)
	}
	keychainUtils.CreateKeyChain(name, strings.Trim(password, "\n"))
	createdKeyChain, err := keychainUtils.GetKeyChain(name)
	if err != nil {
		log.Fatalf("Cannot get created keychain: %v", err)
	}
	return createdKeyChain
}

func readKeychain(name string) *Keychain {
	originKeychain, err := keychainUtils.GetKeyChain(name)
	if err != nil {
		originKeychain = createKeychain(name)
	}
	keychain := &Keychain{
		name: originKeychain.Name,
		keys: make(map[string]Key),
	}

	keys := keychainUtils.GetKeyChainEntities(name)
	for _, originKey := range keys {
		key := Key{
			service:  originKey.Service,
			account:  originKey.Account,
			digits:   len(originKey.Description),
			password: keychainUtils.GetPassword(originKey.Service, keychain.name),
		}
		keychain.keys[originKey.Service] = key
	}
	return keychain
}

func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) add(name string) {
	size := 6
	if *flag7 {
		size = 7
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		size = 8
	}

	_, _ = fmt.Fprintf(os.Stderr, "2f key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	keychainUtils.AddPassword(name, name, text, strings.Repeat("x", size), c.name)
}

func (c *Keychain) delete(name string) {
	keychainUtils.DeletePassword(name, c.name)
}

func (c *Keychain) code(name string) string {
	key, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	code := totp(key.password, time.Now(), key.digits)
	return fmt.Sprintf("%0*d", key.digits, code)
}

func (c *Keychain) show(name string) {
	code := c.code(name)
	fmt.Printf("%s\n", code)
}

func (c *Keychain) showAll() {
	var names []string
	max := 0
	for name, k := range c.keys {
		names = append(names, name)
		if max < k.digits {
			max = k.digits
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%-*s\t%s\n", max, c.code(name), name)
	}
}

func hotp(password string, counter uint64, digits int) int {
	password = strings.Replace(password, " ", "", -1)
	password += strings.Repeat("=", -len(password)&7) // pad to 8 bytes
	decodedPassport, err := decodeKey(password)
	if err != nil {
		log.Fatal(err)
	}
	password = string(decodedPassport)
	h := hmac.New(sha1.New, []byte(password))
	_ = binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(password string, t time.Time, digits int) int {
	return hotp(password, uint64(t.UnixNano())/30e9, digits)
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}
