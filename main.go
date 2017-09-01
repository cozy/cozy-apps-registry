package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cozy/cozy-registry-v3/auth"
	"github.com/cozy/cozy-registry-v3/registry"
	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const envSessionPass = "REGISTRY_SESSION_PASS"

var cfgFileFlag string

var editorRegistry *auth.EditorRegistry
var sessionSecret []byte

func init() {
	flags := rootCmd.PersistentFlags()

	flags.StringVarP(&cfgFileFlag, "config", "c", "", "configuration file")

	flags.String("host", "localhost", "host to listen on")
	checkNoErr(viper.BindPFlag("host", flags.Lookup("host")))

	flags.Int("port", 8080, "port to listen on")
	checkNoErr(viper.BindPFlag("port", flags.Lookup("port")))

	flags.String("couchdb-addr", "localhost:5984", "address of couchdb")
	checkNoErr(viper.BindPFlag("couchdb.addr", flags.Lookup("couchdb-addr")))

	flags.String("couchdb-user", "", "user of couchdb")
	checkNoErr(viper.BindPFlag("couchdb.user", flags.Lookup("couchdb-user")))

	flags.String("couchdb-password", "", "password of couchdb")
	checkNoErr(viper.BindPFlag("couchdb.password", flags.Lookup("couchdb-password")))

	flags.String("couchdb-prefix", "", "prefix for couchdb databases")
	checkNoErr(viper.BindPFlag("couchdb.prefix", flags.Lookup("couchdb-prefix")))

	flags.String("session-secret", "sessionsecret.key", "path to the session secret file")
	checkNoErr(viper.BindPFlag("session-secret", flags.Lookup("session-secret")))

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(genTokenCmd)
	rootCmd.AddCommand(verifyTokenCmd)
	rootCmd.AddCommand(revokeTokensCmd)
	rootCmd.AddCommand(genSessionSecret)
	rootCmd.AddCommand(printPublicKeyCmd)
	rootCmd.AddCommand(verifySignatureCmd)
	rootCmd.AddCommand(addEditorCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		printAndExit(err)
	}
	os.Exit(0)
}

var rootCmd = &cobra.Command{
	Use:           "cozy-registry",
	Short:         "cozy-registry is a registry site to store links to cozy applications",
	Long:          ``,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cfgFileFlag != "" {
			viper.SetConfigFile(cfgFileFlag)
		} else {
			viper.SetConfigName("cozy-registry")
		}
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		err := viper.ReadInConfig()
		if err != nil {
			cmd.Help()
			fmt.Fprintln(os.Stderr)
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var serveCmd = &cobra.Command{
	Use:     "serve",
	Short:   `Start the registry HTTP server`,
	PreRunE: compose(loadSessionSecret, prepareRegistry),
	RunE: func(cmd *cobra.Command, args []string) error {
		address := viper.GetString("host") + ":" + strconv.Itoa(viper.GetInt("port"))
		fmt.Printf("Listening on %s...\n", address)
		return StartRouter(address)
	},
}

var printPublicKeyCmd = &cobra.Command{
	Use:     "pubkey [editor]",
	Short:   `Print the PEM encoded public key of the specified editor`,
	PreRunE: prepareRegistry,
	RunE: func(cmd *cobra.Command, args []string) error {
		editor, _, err := fetchEditor(args)
		if err != nil {
			return err
		}
		fmt.Print(editor.MarshalPublicKeyPEM())
		return nil
	},
}

var verifySignatureCmd = &cobra.Command{
	Use:     "verify [editor] [file]",
	Short:   `Verify a signature given via stdin for a specified editor and file`,
	PreRunE: prepareRegistry,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		editor, args, err := fetchEditor(args)
		if err != nil {
			return err
		}
		if len(args) == 0 {
			return fmt.Errorf("Missing argument for file path")
		}

		fmt.Fprintf(os.Stderr, "Waiting for signature on stdin...")
		signature, err := ioutil.ReadAll(io.LimitReader(os.Stdin, 10*1024))
		if err != nil {
			return fmt.Errorf("Error reading signature on stdin: %s", err)
		}

		fmt.Fprintln(os.Stderr, "ok")
		filePath := registry.AbsPath(args[0])
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("Failed to open file %q: %s", filePath, err)
		}
		defer f.Close()

		hash := sha256.New()
		_, err = io.Copy(hash, f)
		if err != nil {
			return fmt.Errorf("Could not read file %q: %s", filePath, err)
		}
		hashed := hash.Sum(nil)

		signatureB64, err := base64.StdEncoding.DecodeString(string(signature))
		if err == nil {
			signature = signatureB64
		}

		fmt.Fprintf(os.Stderr, "Checking signature...")
		if !editor.VerifySignature(hashed, signature) {
			return fmt.Errorf("failed: bad signature")
		}
		fmt.Fprintln(os.Stderr, "ok")

		return nil
	},
}

var genTokenCmd = &cobra.Command{
	Use:     "gen-token [editor] [max-age]",
	Short:   `Generate a token for the specified editor`,
	PreRunE: compose(loadSessionSecret, prepareRegistry),
	RunE: func(cmd *cobra.Command, args []string) error {
		editor, rest, err := fetchEditor(args)
		if err != nil {
			return err
		}

		var maxAge time.Duration
		if len(rest) > 0 {
			maxAge, err = time.ParseDuration(rest[0])
			if err != nil {
				return fmt.Errorf("Could not parse max-age argument: %s", err)
			}
		}

		token, err := editor.GenerateSessionToken(sessionSecret, maxAge)
		if err != nil {
			return fmt.Errorf("Could not generate editor token for %q: %s",
				editor.Name(), err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(token))
		return nil
	},
}

var verifyTokenCmd = &cobra.Command{
	Use:     "verify-token [editor] [token]",
	Short:   `Verify a token given via stdin for the specified editor`,
	PreRunE: compose(loadSessionSecret, prepareRegistry),
	RunE: func(cmd *cobra.Command, args []string) error {
		editor, rest, err := fetchEditor(args)
		if err != nil {
			return err
		}

		var token []byte
		if len(rest) > 0 && rest[0] != "-" {
			token = []byte(rest[0])
		} else {
			fmt.Fprintf(os.Stderr, "Waiting for token on stdin...")
			token, err = ioutil.ReadAll(io.LimitReader(os.Stdin, 10*1024))
			if err != nil {
				return fmt.Errorf("Error reading token on stdin: %s", err)
			}
			fmt.Fprintln(os.Stderr, "ok")
		}

		tokenB64, err := base64.StdEncoding.DecodeString(string(token))
		if err == nil {
			token = tokenB64
		}

		fmt.Fprintf(os.Stderr, "Checking token...")
		if !editor.VerifySessionToken(sessionSecret, token) {
			return fmt.Errorf("failed: bad token")
		}
		fmt.Fprintln(os.Stderr, "ok")
		return nil
	},
}

var revokeTokensCmd = &cobra.Command{
	Use:     "revoke-tokens [editor] [token]",
	Short:   `Revoke all tokens that have been generated for the specified editor`,
	PreRunE: compose(loadSessionSecret, prepareRegistry),
	RunE: func(cmd *cobra.Command, args []string) error {
		editor, rest, err := fetchEditor(args)
		if err != nil {
			return err
		}

		var tokenVal string
		if len(rest) == 0 {
			tokenVal = prompt("Token:")
		} else {
			tokenVal = rest[0]
		}

		token, err := base64.StdEncoding.DecodeString(tokenVal)
		if err != nil {
			return fmt.Errorf("Token is not properly base64 encoded: %s", err)
		}

		if !askQuestion(true, "Are you sure you want to revoke tokens from %q ?", editor.Name()) {
			return nil
		}
		return editorRegistry.RevokeSessionTokens(editor, sessionSecret, token)
	},
}

var genSessionSecret = &cobra.Command{
	Use:   "gen-session-secret [path]",
	Short: `Generate a session secret file`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var filePath string
		if len(args) == 0 {
			filePath = viper.GetString("session-secret")
		}
		if filePath == "" {
			return fmt.Errorf("Missing file path to generate the secret")
		}

		fmt.Printf("Creating file %q... ", filePath)
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_EXCL, 0660)
		if err != nil {
			return err
		}
		fmt.Println("ok")
		defer file.Close()

		var passphrase []byte
		for {
			passphrase = askPassword("Enter passphrase (empty for no passphrase): ")
			if len(passphrase) == 0 {
				if askQuestion(false, "Are you sure you do NOT want to encrypt the session secret ?") {
					break
				} else {
					continue
				}
			}
			if c := askPassword("Confirm passphrase: "); !bytes.Equal(passphrase, c) {
				fmt.Fprintln(os.Stderr, "Passphrases do not match. Please retry.")
				continue
			}
			break
		}

		secret := auth.GenerateMasterSecret()

		if len(passphrase) > 0 {
			secret, err = auth.EncryptMasterSecret(secret, passphrase)
			if err != nil {
				return fmt.Errorf("Failed to encrypt session secret: %s", err)
			}
		}

		_, err = fmt.Fprintln(file, base64.StdEncoding.EncodeToString(secret))
		return err
	},
}

var addEditorCmd = &cobra.Command{
	Use:     "add-editor [editor]",
	Short:   `Add an editor to the registry though an interactive CLI`,
	PreRunE: prepareRegistry,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var editorName string
		for {
			editorName, _, err = getEditorName(args)
			if err != nil {
				return err
			}
			_, err = editorRegistry.GetEditor(editorName)
			if err == nil {
				fmt.Fprintln(os.Stderr, auth.ErrEditorExists)
				continue
			}
			break
		}

		associatePublicKey := askQuestion(false, "Associate a public key to the editor %q ?", editorName)
		if associatePublicKey {
			var encodedPublicKey []byte

			for {
				var publicKeyPath string
				var publicKeyFile *os.File

				publicKeyPath = prompt("Path to public key file:")

				publicKeyPath = registry.AbsPath(publicKeyPath)
				publicKeyFile, err = os.Open(publicKeyPath)
				if err != nil {
					fmt.Printf("Error while loading file %q: %s.\nPlease retry.\n\n",
						publicKeyPath, err.Error())
					continue
				}

				encodedPublicKey, err = ioutil.ReadAll(io.LimitReader(publicKeyFile, 10*1024))
				if err != nil {
					fmt.Printf("Error while loading file %q: %s.\nPlease retry.\n\n",
						publicKeyPath, err.Error())
					continue
				}

				break
			}

			fmt.Printf("Creating new editor with given public key...")
			_, err = editorRegistry.CreateEditorWithPublicKey(editorName, encodedPublicKey)
		} else {
			fmt.Printf("Creating new editor...")
			_, err = editorRegistry.CreateEditorWithoutPublicKey(editorName)
		}
		if err != nil {
			fmt.Println("failed.")
			return err
		}

		fmt.Println("ok")
		return nil
	},
}

func prepareRegistry(cmd *cobra.Command, args []string) error {
	client, err := registry.InitDBClient(
		viper.GetString("couchdb.addr"),
		viper.GetString("couchdb.user"),
		viper.GetString("couchdb.password"),
		viper.GetString("couchdb.prefix"))
	if err != nil {
		return fmt.Errorf("Could not reach CouchDB: %s", err)
	}

	vault, err := auth.NewCouchdbVault(client, registry.EditorsDB)
	if err != nil {
		return fmt.Errorf("Could not create vault: %s", err)
	}

	editorRegistry, err = auth.NewEditorRegistry(vault)
	if err != nil {
		return fmt.Errorf("Error while loading editor registry: %s", err)
	}
	return nil
}

func loadSessionSecret(cmd *cobra.Command, args []string) error {
	sessionSecretPath := viper.GetString("session-secret")
	if sessionSecretPath == "" {
		return fmt.Errorf("Missing path to session secret file")
	}

	wd, _ := os.Getwd()
	absPath := registry.AbsPath(sessionSecretPath)
	relPath, _ := filepath.Rel(wd, absPath)

	f, err := os.Open(absPath)
	if os.IsNotExist(err) {
		printAndExit(`Could not find session secret file: %q.

Consider using the "gen-session-secret" command to generate the file and adding
it to you configuration file.`, relPath)
	}
	if err != nil {
		return err
	}

	var data []byte
	{
		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, f)
		if err != nil {
			return err
		}
		data = buf.Bytes()
	}

	data, err = base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("Session secret is not properly base64 encoded in %q: %s",
			relPath, err)
	}

	if auth.IsSecretClear(data) {
		sessionSecret = data
		return nil
	}

	{
		envPassphrase := []byte(os.Getenv(envSessionPass))
		if len(envPassphrase) > 0 {
			sessionSecret, err = auth.DecryptMasterSecret(data, envPassphrase)
			if err != nil {
				return fmt.Errorf("Could not decrypt session secret: %s", err)
			}
			return nil
		}
	}

	for {
		passphrase := askPassword("Enter passphrase (decrypting session secret): ")
		sessionSecret, err = auth.DecryptMasterSecret(data, passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not decrypt session secret: %s\n", err)
			continue
		}
		return nil
	}
}

func getEditorName(args []string) (editorName string, rest []string, err error) {
	if len(args) > 0 {
		editorName, rest = args[0], args[1:]
		err = auth.CkeckEditorName(editorName)
		return
	}
	for {
		editorName = prompt("Editor name:")
		if err = auth.CkeckEditorName(editorName); err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			continue
		}
		return
	}
}

func fetchEditor(args []string) (editor *auth.Editor, rest []string, err error) {
	var editorName string
	editorName, rest, err = getEditorName(args)
	if err != nil {
		return
	}
	editor, err = editorRegistry.GetEditor(editorName)
	if err != nil {
		err = fmt.Errorf("Error while getting editor: %s", err)
	}
	return
}

func readLine() string {
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		printAndExit(err)
	}
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
}

func prompt(text string, a ...interface{}) string {
	fmt.Fprintf(os.Stderr, text+" ", a...)
	return readLine()
}

func askQuestion(defaultResponse bool, question string, a ...interface{}) bool {
	if defaultResponse {
		question += " [Y/n] "
	} else {
		question += " [y/N] "
	}
	fmt.Fprintf(os.Stderr, question, a...)
	for {
		resp := readLine()
		switch strings.ToLower(resp) {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		case "":
			return defaultResponse
		default:
			fmt.Printf(`Respond with "yes" or "no": `)
			continue
		}
	}
}

func askPassword(prompt ...string) []byte {
	if len(prompt) == 0 {
		fmt.Fprintf(os.Stderr, "Enter passphrase: ")
	} else {
		fmt.Fprintf(os.Stderr, prompt[0])
	}
	pass, err := gopass.GetPasswdPrompt("", false, os.Stdin, os.Stderr)
	if err != nil {
		printAndExit(err)
	}
	return pass
}

func compose(hooks ...func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		for _, hook := range hooks {
			if err := hook(cmd, args); err != nil {
				return err
			}
		}
		return nil
	}
}

func printAndExit(v interface{}, a ...interface{}) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", v), a...)
	os.Exit(1)
}

func checkNoErr(err error) {
	if err != nil {
		panic(err)
	}
}
