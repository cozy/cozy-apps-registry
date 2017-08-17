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
	"strconv"
	"strings"
	"time"

	"github.com/cozy/cozy-registry-v3/auth"
	"github.com/cozy/cozy-registry-v3/registry"
	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
)

var editorRegistry *auth.EditorRegistry

var portFlag int
var hostFlag string
var couchAddrFlag string
var couchUserFlag string
var couchPassFlag string
var secretPath string
var secretPassphrase string

var masterSecret []byte

func init() {
	rootCmd.PersistentFlags().IntVar(&portFlag, "port", 8080, "specify the port to listen on")
	rootCmd.PersistentFlags().StringVar(&hostFlag, "host", "localhost", "specify the host to listen on")
	rootCmd.PersistentFlags().StringVar(&couchAddrFlag, "couchdb-addr", "localhost:5984", "specify the address of couchdb")
	rootCmd.PersistentFlags().StringVar(&couchUserFlag, "couchdb-user", "", "specify the user of couchdb")
	rootCmd.PersistentFlags().StringVar(&couchPassFlag, "couchdb-password", "", "specify the password of couchdb")
	rootCmd.PersistentFlags().StringVar(&secretPath, "session-file", "sessionsecret", "path to the master session secret file")
	rootCmd.PersistentFlags().StringVar(&secretPassphrase, "session-pass", "", "passphrase to decrypt the session secret file")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(printPublicKeyCmd)
	rootCmd.AddCommand(verifySignatureCmd)
	rootCmd.AddCommand(genTokenCmd)
	rootCmd.AddCommand(verifyTokenCmd)
	rootCmd.AddCommand(revokeTokensCmd)
	rootCmd.AddCommand(addEditorCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		printAndExit(err.Error())
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
		secretPath = registry.AbsPath(secretPath)

		client, err := registry.InitDBClient(couchAddrFlag, couchUserFlag, couchPassFlag)
		if err != nil {
			printAndExit("Could not reach CouchDB: %s", err)
		}

		vault, err := auth.NewCouchdbVault(client, registry.EditorsDB)
		if err != nil {
			printAndExit("Could not create vault: %s", err)
		}

		editorRegistry, err = auth.NewEditorRegistry(vault)
		if err != nil {
			printAndExit("Error while loading editor registry: %s", err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var serveCmd = &cobra.Command{
	Use:    "serve",
	Short:  `Start the registry HTTP server`,
	PreRun: loadMasterSecret,
	RunE: func(cmd *cobra.Command, args []string) error {
		address := hostFlag + ":" + strconv.Itoa(portFlag)
		fmt.Printf("Listening on %s...\n", address)
		return StartRouter(address)
	},
}

var printPublicKeyCmd = &cobra.Command{
	Use:   "pubkey [editor]",
	Short: `Print the PEM encoded public key of the specified editor`,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, _, err := getEditorName(args)
		if err != nil {
			return err
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return err
		}

		fmt.Print(editor.MarshalPublicKeyPEM())
		return nil
	},
}

var verifySignatureCmd = &cobra.Command{
	Use:   "verify [editor] [file]",
	Short: `Verify a signature given via stdin for a specified editor and file`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var editorName string
		editorName, args, err = getEditorName(args)
		if err != nil {
			return err
		}
		if len(args) == 0 {
			return fmt.Errorf("Missing argument for file path")
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
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
			return fmt.Errorf("Failed to open file %s: %s", filePath, err)
		}
		defer f.Close()

		hash := sha256.New()
		_, err = io.Copy(hash, f)
		if err != nil {
			return fmt.Errorf("Could not read file %s: %s", filePath, err)
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
	Use:    "gen-token [editor] [max-age]",
	Short:  `Generate a token for the specified editor`,
	PreRun: loadMasterSecret,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, rest, err := getEditorName(args)
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

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}

		token, err := editor.GenerateSessionToken(masterSecret, maxAge)
		if err != nil {
			return fmt.Errorf("Could not generate editor token for %s: %s",
				editorName, err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(token))
		return nil
	},
}

var verifyTokenCmd = &cobra.Command{
	Use:    "verify-token [editor] [token]",
	Short:  `Verify a token given via stdin for the specified editor`,
	PreRun: loadMasterSecret,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, rest, err := getEditorName(args)
		if err != nil {
			return err
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
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
		if !editor.VerifySessionToken(masterSecret, token) {
			return fmt.Errorf("failed: bad token")
		}
		fmt.Fprintln(os.Stderr, "ok")
		return nil
	},
}

var revokeTokensCmd = &cobra.Command{
	Use:    "revoke-tokens [editor] [token]",
	Short:  `Revoke all tokens that have been generated for the specified editor`,
	PreRun: loadMasterSecret,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, rest, err := getEditorName(args)
		if err != nil {
			return err
		}
		if len(rest) == 0 {
			return fmt.Errorf("Missing currently correct token to revoke")
		}

		token, err := base64.StdEncoding.DecodeString(rest[0])
		if err != nil {
			return fmt.Errorf("Token is not properly base64 encoded: %s", err)
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}

		return editorRegistry.RevokeSessionTokens(editor, masterSecret, token)
	},
}

var addEditorCmd = &cobra.Command{
	Use:   "add-editor [editor]",
	Short: `Add an editor to the registry though an interactive CLI`,
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

		associatePublicKey := askQuestion(false, "Associate a public key to the editor '%s' ?", editorName)
		if associatePublicKey {
			var encodedPublicKey []byte

			for {
				var publicKeyPath string
				var publicKeyFile *os.File

				fmt.Fprintf(os.Stderr, "Path to public key file: ")
				publicKeyPath = readLine()

				publicKeyPath = registry.AbsPath(publicKeyPath)
				publicKeyFile, err = os.Open(publicKeyPath)
				if err != nil {
					fmt.Printf("Error while loading file '%s': %s.\nPlease retry.\n\n",
						publicKeyPath, err.Error())
					continue
				}

				encodedPublicKey, err = ioutil.ReadAll(io.LimitReader(publicKeyFile, 10*1024))
				if err != nil {
					fmt.Printf("Error while loading file '%s': %s.\nPlease retry.\n\n",
						publicKeyPath, err.Error())
					continue
				}

				break
			}

			fmt.Printf("\nCreating new editor with given public key...")
			_, err = editorRegistry.CreateEditorWithPublicKey(editorName, encodedPublicKey)
		} else {
			fmt.Printf("\nCreating new editor...")
			_, err = editorRegistry.CreateEditorWithoutPublicKey(editorName)
		}
		if err != nil {
			fmt.Println("failed.")
			return err
		}

		fmt.Println("ok.")
		return nil
	},
}

func loadMasterSecret(cmd *cobra.Command, args []string) {
	passphrase := []byte(secretPassphrase)
	for {
		var err error
		masterSecret, err = auth.GetMasterSecret(secretPath, passphrase)
		if os.IsNotExist(err) {
			resp := askQuestion(true, "Secret session file does not exist.\nWould you like to generate it ?")
			if !resp {
				printAndExit("Interrupted")
			}
			for {
				fmt.Fprint(os.Stderr, "\n")
				passphrase = askPassword("Enter passphrase (empty for no passphrase): ")
				if len(passphrase) == 0 {
					if askQuestion(false, "Are you sure you do NOT want to encrypt the session secret ?") {
						break
					} else {
						continue
					}
				}
				if c := askPassword("Confirm passphrase: "); bytes.Equal(passphrase, c) {
					break
				}
				fmt.Fprintln(os.Stderr, "Passphrases do not match. Please retry.")
			}
			err = auth.GenerateMasterSecret(secretPath, passphrase)
			if err != nil {
				printAndExit("Failed to generate session secret file: %s", err)
			}
			fmt.Print("\nSession secret file created successfully.\n\n")
			continue
		}
		if err == auth.ErrMissingPassphrase && len(passphrase) == 0 {
			passphrase = askPassword("Enter passphrase (decrypting session secret): ")
			continue
		}
		if err != nil {
			printAndExit("Error while loading session secret file: %s", err)
		}
		break
	}
}

func getEditorName(args []string) (editorName string, rest []string, err error) {
	if len(args) > 0 {
		editorName, rest = args[0], args[1:]
		err = auth.CkeckEditorName(editorName)
		return
	}
	for {
		fmt.Fprintf(os.Stderr, "Editor name: ")
		editorName = readLine()
		if err = auth.CkeckEditorName(editorName); err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			continue
		}
		return
	}
}

func readLine() string {
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		printAndExit(err.Error())
	}
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
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
		printAndExit(err.Error())
	}
	return pass
}

func printAndExit(v string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, v+"\n", a...)
	os.Exit(1)
}
