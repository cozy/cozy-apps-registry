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
	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
)

var editorRegistry *auth.EditorRegistry

var portFlag int
var hostFlag string
var couchAddrFlag string
var couchUserFlag string
var couchPassFlag string
var editorRegistryFlag string

func init() {
	rootCmd.PersistentFlags().IntVar(&portFlag, "port", 8080, "specify the port to listen on")
	rootCmd.PersistentFlags().StringVar(&hostFlag, "host", "localhost", "specify the host to listen on")
	rootCmd.PersistentFlags().StringVar(&couchAddrFlag, "couchdb-addr", "localhost:5984", "specify the address of couchdb")
	rootCmd.PersistentFlags().StringVar(&couchUserFlag, "couchdb-user", "", "specify the user of couchdb")
	rootCmd.PersistentFlags().StringVar(&couchPassFlag, "couchdb-password", "", "specify the password of couchdb")
	rootCmd.PersistentFlags().StringVar(&editorRegistryFlag, "editor-registry", "couchdb", "used to specify the editors registry (file:./filename or couchdb)")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(genSignatureCmd)
	rootCmd.AddCommand(genTokenCmd)
	rootCmd.AddCommand(verifyTokenCmd)
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
		err := InitDBClient(couchAddrFlag, couchUserFlag, couchPassFlag)
		if err != nil {
			printAndExit("Could not reach CouchDB: %s", err)
		}

		regOpts := strings.SplitN(editorRegistryFlag, ":", 2)
		var vault auth.EditorVault
		switch regOpts[0] {
		case "file":
			if len(regOpts) != 2 {
				printAndExit("Bad -editor-registry option: missing filename (ie -editor-registry text:./filename)")
			}
			filename := regOpts[1]
			vault, err = auth.NewFileVault(filename)
		case "couch", "couchdb":
			vault, err = auth.NewCouchdbVault(client, editorsDB)
		default:
			printAndExit("Bad -editor-registry option: unknown type %s", regOpts[0])
		}
		if err != nil {
			printAndExit("Could not initialize the editor registry: %s", err)
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
	Use: "serve",
	RunE: func(cmd *cobra.Command, args []string) error {
		address := hostFlag + ":" + strconv.Itoa(portFlag)
		fmt.Printf("Listening on %s...\n", address)
		return StartRouter(address)
	},
}

var genSignatureCmd = &cobra.Command{
	Use: "sign [editor]",
	RunE: func(cmd *cobra.Command, args []string) error {
		var password []byte
		if len(args) < 1 {
			return fmt.Errorf("Missing argument for editor name")
		}
		if len(args) < 2 {
			return fmt.Errorf("Missing path to file to sign")
		}
		editorName, filePath := args[0], args[1]
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("Failed to open file %s: %s", filePath, err)
		}
		editor, err := editorRegistry.GetEditor(editorName)
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}
		if !editor.HasPrivateKey() {
			return fmt.Errorf("Editor %s has no private key stored in the registry",
				editor.Name())
		}
		if editor.HasEncryptedPrivateKey() {
			fmt.Printf("Password: ")
			password, err = gopass.GetPasswdMasked()
			if err != nil {
				return err
			}
		}
		hash := sha256.New()
		_, err = io.Copy(hash, f)
		if err != nil {
			return fmt.Errorf("Could not read file %s: %s", filePath, err)
		}
		hashed := hash.Sum(nil)
		signature, err := editor.GenerateSignature(hashed, password)
		if err != nil {
			return fmt.Errorf("Could not generate editor signature for %s: %s",
				filePath, err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(signature))
		return nil
	},
}

var genTokenCmd = &cobra.Command{
	Use: "gen-token [editor]",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("Missing argument for editor name")
		}
		var password []byte
		editor, err := editorRegistry.GetEditor(args[0])
		if err != nil {
			return fmt.Errorf("Error while getting editor: %s", err)
		}
		if !editor.HasPrivateKey() {
			return fmt.Errorf("Editor %s has no private key stored in the registry",
				editor.Name())
		}
		if editor.HasEncryptedPrivateKey() {
			fmt.Printf("Password: ")
			password, err = gopass.GetPasswdMasked()
			if err != nil {
				return err
			}
		}
		token, err := editor.GenerateToken(password)
		if err != nil {
			return fmt.Errorf("Could not generate editor token for %s: %s",
				args[0], err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(token))
		return nil
	},
}

var verifyTokenCmd = &cobra.Command{
	Use: "verify-token [editor]",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("Missing argument for editor name")
		}
		editor, err := editorRegistry.GetEditor(args[0])
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
		token, err = base64.StdEncoding.DecodeString(string(token))
		if err != nil {
			return fmt.Errorf("Signature is not base64 encoded: %s", err)
		}
		fmt.Fprintf(os.Stderr, "Checking token...")
		ok, err := editor.VerifyToken(token)
		if err != nil {
			return fmt.Errorf("failed: not properly encoded: %s", err)
		}
		if !ok {
			return fmt.Errorf("failed: bad token")
		}
		fmt.Fprintln(os.Stderr, "ok")
		return nil
	},
}

var addEditorCmd = &cobra.Command{
	Use: "add-editor [editor]",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		stdin := bufio.NewReader(os.Stdin)

		var editorName string
		if len(args) == 0 {
			for {
				fmt.Printf("Editor name: ")
				editorName, err = readLine(stdin)
				if err != nil {
					return err
				}
				if err = auth.MatchEditorName(editorName); err != nil {
					fmt.Println(err.Error())
					continue
				}
				_, err = editorRegistry.GetEditor(editorName)
				if err == nil {
					fmt.Printf("Editor \"%s\" already exists\n", editorName)
					continue
				}
				break
			}
		} else {
			editorName = args[0]
		}

		var privateKeyPassword []byte
		var editor *auth.Editor

		genPrivateKey, err := askQuestion(stdin, "Generate a new private key for editor \"%s\" ?", editorName)
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
				fmt.Printf("Password: ")
				privateKeyPassword, err = gopass.GetPasswdMasked()
				if err != nil {
					return err
				}

				if len(privateKeyPassword) == 0 {
					var noEncrypt bool
					noEncrypt, err = askQuestion(stdin,
						"No password given, are you sure you do *not* want to encrypt your private key ?")
					if err != nil {
						return err
					}
					if !noEncrypt {
						continue
					}
					break
				}

				fmt.Printf("Confirm: ")
				passwordConfirmation, err := gopass.GetPasswdMasked()
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
			editor, err = auth.CreateEditorAndPrivateKey(editorName, privateKeyPassword)
			if err != nil {
				fmt.Println("failed.")
				return err
			}
		} else {
			var encodedPublicKey []byte

			for {
				fmt.Printf("Path to public key file: ")
				publicKeyPath, err := readLine(stdin)
				if err != nil {
					return err
				}

				publicKeyFile, err := os.Open(publicKeyPath)
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
			editor, err = auth.CreateEditorWithPublicKey(editorName, encodedPublicKey)
			if err != nil {
				fmt.Println("failed.")
				return err
			}
		}
		fmt.Println("ok.")

		if err = editorRegistry.AddEditor(editor); err != nil {
			return fmt.Errorf("Could not add a new editor: %s", err)
		}

		return nil
	},
}

func readLine(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil {
		return s, err
	}
	if len(s) == 0 {
		return s, nil
	}
	return s[:len(s)-1], nil
}

func askQuestion(r *bufio.Reader, question string, a ...interface{}) (bool, error) {
	for {
		fmt.Printf(question+" [y/N] ", a...)
		resp, err := readLine(r)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(resp) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		default:
			fmt.Println(`Please respond with with "yes" or "no"`)
			continue
		}
	}
}

func printAndExit(v string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, v+"\n", a...)
	os.Exit(1)
}
