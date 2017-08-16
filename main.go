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

func init() {
	rootCmd.PersistentFlags().IntVar(&portFlag, "port", 8080, "specify the port to listen on")
	rootCmd.PersistentFlags().StringVar(&hostFlag, "host", "localhost", "specify the host to listen on")
	rootCmd.PersistentFlags().StringVar(&couchAddrFlag, "couchdb-addr", "localhost:5984", "specify the address of couchdb")
	rootCmd.PersistentFlags().StringVar(&couchUserFlag, "couchdb-user", "", "specify the user of couchdb")
	rootCmd.PersistentFlags().StringVar(&couchPassFlag, "couchdb-password", "", "specify the password of couchdb")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(printPublicKeyCmd)
	rootCmd.AddCommand(printPrivateKeyCmd)
	rootCmd.AddCommand(genSignatureCmd)
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
	Use:   "serve",
	Short: `Start the registry HTTP server`,
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

		fmt.Print(editor.MarshalPublickKeyPEM())
		return nil
	},
}

var printPrivateKeyCmd = &cobra.Command{
	Use:   "privkey [editor]",
	Short: `Print the PEM encoded private key of the specified editor`,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, _, err := getEditorName(args)
		if err != nil {
			return err
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return err
		}

		var password []byte
		if !editor.HasPrivateKey() {
			return fmt.Errorf("Editor %s has no private key stored in the registry",
				editor.Name())
		}
		if editor.HasEncryptedPrivateKey() {
			password, err = askPassword()
			if err != nil {
				return err
			}
		}

		privateKeyPEM, err := editor.MarshalPrivateKeyPEM(password)
		if err != nil {
			return err
		}

		fmt.Print(privateKeyPEM)
		return nil
	},
}

var genSignatureCmd = &cobra.Command{
	Use:   "sign [editor] [file]",
	Short: `Generate a signature for a specified editor and file`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var editorName string
		editorName, args, err = getEditorName(args)
		if err != nil {
			return err
		}

		var r io.Reader
		if len(args) > 0 && args[0] != "-" {
			var f *os.File
			filePath := registry.AbsPath(args[1])
			f, err = os.Open(filePath)
			if err != nil {
				return fmt.Errorf("Failed to open file %s: %s", filePath, err)
			}
			defer f.Close()
			r = f
		} else {
			r = os.Stdin
		}

		var password []byte
		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}
		if !editor.HasPrivateKey() {
			return fmt.Errorf("Editor %s has no private key stored in the registry",
				editor.Name())
		}
		if editor.HasEncryptedPrivateKey() {
			password, err = askPassword()
			if err != nil {
				return err
			}
		}

		hash := sha256.New()
		_, err = io.Copy(hash, r)
		if err != nil {
			return fmt.Errorf("Error while reading file: %s", err)
		}
		hashed := hash.Sum(nil)

		signature, err := editor.GenerateSignature(hashed, password)
		if err != nil {
			return fmt.Errorf("Could not generate editor signature: %s", err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(signature))
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
	Use:   "gen-token [editor]",
	Short: `Generate a token for the specified editor`,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, _, err := getEditorName(args)
		if err != nil {
			return err
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}
		if !editor.HasPrivateKey() {
			return fmt.Errorf("Editor %s has no private key stored in the registry",
				editor.Name())
		}
		var password []byte
		if editor.HasEncryptedPrivateKey() {
			password, err = askPassword()
			if err != nil {
				return err
			}
		}

		token, err := editor.GenerateSessionToken(password)
		if err != nil {
			return fmt.Errorf("Could not generate editor token for %s: %s",
				editorName, err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(token))
		return nil
	},
}

var verifyTokenCmd = &cobra.Command{
	Use:   "verify-token [editor]",
	Short: `Verify a token given via stdin for the specified editor`,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, _, err := getEditorName(args)
		if err != nil {
			return err
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}
		if !editor.HasPrivateKey() {
			return fmt.Errorf("Editor %s has no private key stored in the registry",
				editor.Name())
		}

		fmt.Fprintf(os.Stderr, "Waiting for token on stdin...")
		token, err := ioutil.ReadAll(io.LimitReader(os.Stdin, 10*1024))
		if err != nil {
			return fmt.Errorf("Error reading token on stdin: %s", err)
		}
		fmt.Fprintln(os.Stderr, "ok")

		tokenB64, err := base64.StdEncoding.DecodeString(string(token))
		if err == nil {
			token = tokenB64
		}

		fmt.Fprintf(os.Stderr, "Checking token...")
		if !editor.VerifySessionToken(token) {
			return fmt.Errorf("failed: bad token")
		}
		fmt.Fprintln(os.Stderr, "ok")
		return nil
	},
}

var revokeTokensCmd = &cobra.Command{
	Use:   "revoke-tokens [editor]",
	Short: `Revoke all tokens that have been generated for the specified editor`,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, _, err := getEditorName(args)
		if err != nil {
			return err
		}

		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}

		return editorRegistry.RevokeSessionTokens(editor)
	},
}

var addEditorCmd = &cobra.Command{
	Use:   "add-editor [editor]",
	Short: `Add an editor to the registry though an interactive CLI`,
	RunE: func(cmd *cobra.Command, args []string) error {
		editorName, _, err := getEditorName(args)
		if err != nil {
			return err
		}
		_, err = editorRegistry.GetEditor(editorName)
		if err == nil {
			fmt.Printf("Editor \"%s\" already exists\n", editorName)
		}

		var privateKeyPassword []byte
		genPrivateKey, err := askQuestion(true, "Generate a new private key for editor \"%s\" ?", editorName)
		if err != nil {
			return err
		}

		if genPrivateKey {
			fmt.Printf(`
We are going to generate an new private/public key pair that are going to be
stored and associated with the editor. The generated private key is
ECDSA P-256, it will be encrypted using AES-256-GCM with a key derived from a
password of your choosing. The derivation function used on the password is
scrypt with a 16 bytes salt.

To add an application, you will be able to use the cozy-registry-v3 tool or to
generate a token or sign an application for you.

`)

			for {
				privateKeyPassword, err = askPassword()
				if err != nil {
					return err
				}

				if len(privateKeyPassword) == 0 {
					var noEncrypt bool
					noEncrypt, err = askQuestion(true, "No password given. Do NOT want to encrypt the private key ?")
					if err != nil {
						return err
					}
					if !noEncrypt {
						continue
					}
					break
				}

				var passwordConfirmation []byte
				passwordConfirmation, err = askPassword("Confirm passphrase: ")
				if err != nil {
					return err
				}
				if !bytes.Equal(privateKeyPassword, passwordConfirmation) {
					fmt.Printf("Password missmatch. Please retry.\n\n")
					continue
				}
				break
			}
		}

		if genPrivateKey {
			fmt.Printf("\nCreating new editor and key pair...")
			_, err = editorRegistry.CreateEditorAndPrivateKey(editorName, privateKeyPassword)
			if err != nil {
				fmt.Println("failed.")
				return err
			}
		} else {
			var encodedPublicKey []byte

			for {
				fmt.Printf("Path to public key file: ")
				var publicKeyPath string
				var publicKeyFile *os.File
				publicKeyPath, err = readLine()
				if err != nil {
					return err
				}

				publicKeyPath = registry.AbsPath(publicKeyPath)
				publicKeyFile, err = os.Open(publicKeyPath)
				if os.IsNotExist(err) {
					fmt.Printf("File %s does not exist. Please retry.\n", publicKeyPath)
					continue
				}
				if err != nil {
					return err
				}

				encodedPublicKey, err = ioutil.ReadAll(io.LimitReader(publicKeyFile, 10*1024))
				if err != nil {
					return err
				}

				break
			}

			fmt.Printf("\nCreating new editor with given public key...")
			_, err = editorRegistry.CreateEditorWithPublicKey(editorName, encodedPublicKey)
			if err != nil {
				fmt.Println("failed.")
				return err
			}
		}

		fmt.Println("ok.")
		return nil
	},
}

func getEditorName(args []string) (editorName string, rest []string, err error) {
	if len(args) > 0 {
		editorName, rest = args[0], args[1:]
		err = auth.CkeckEditorName(editorName)
		return
	}
	for {
		fmt.Printf("Editor name: ")
		editorName, err = readLine()
		if err != nil {
			return
		}
		if err = auth.CkeckEditorName(editorName); err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			continue
		}
		return
	}
}

func readLine() (string, error) {
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		return s, err
	}
	if len(s) == 0 {
		return s, nil
	}
	return s[:len(s)-1], nil
}

func askQuestion(defaultResponse bool, question string, a ...interface{}) (bool, error) {
	if defaultResponse {
		question += " [Y/n] "
	} else {
		question += " [y/N] "
	}
	fmt.Printf(question, a...)
	for {
		resp, err := readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(resp) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		case "":
			return defaultResponse, nil
		default:
			fmt.Printf(`Respond with "yes" or "no": `)
			continue
		}
	}
}

func askPassword(prompt ...string) ([]byte, error) {
	if len(prompt) == 0 {
		fmt.Fprintf(os.Stderr, "Enter passphrase: ")
	} else {
		fmt.Fprintf(os.Stderr, prompt[0])
	}
	return gopass.GetPasswdPrompt("", false, os.Stdin, os.Stderr)
}

func printAndExit(v string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, v+"\n", a...)
	os.Exit(1)
}
