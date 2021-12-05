package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/datahop/ipfs-lite/pkg/store"
	"github.com/manifoldco/promptui"
	"github.com/onepeerlabs/wimp/pkg/manager"
	generator "github.com/sethvargo/go-password/password"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
	"golang.design/x/clipboard"
)

const (
	DefaultPrompt = "wimp"
	Separator     = ">>>"

	passwordPrefix     = "/password/"
	passwordMetaPrefix = "/meta/"
	mnemonicTag        = "/mnemonic"
)

var (
	absoluteRoot = ""
	passwordManager         *manager.Manager
)

type PasswordMetaInfo struct {
	Domain      string
	Username    string
	Description string
}

func initPrompt() {
	usr, err := user.Current()
	if err != nil {
		fmt.Printf("Failed getting user home directory. Is USER set?\n")
		os.Exit(1)
	}

	secretPrompt := promptui.Prompt{
		Label: "Connectivity Secret ",
		Mask:  '*',
	}
	secret, _ := secretPrompt.Run()

	absoluteRoot = usr.HomeDir + string(os.PathSeparator) + root

	passwordManager, err = manager.New(context.Background(), absoluteRoot, port, secret)
	if err != nil {
		fmt.Printf("Failed creating password manager %s\n", err.Error())
		os.Exit(1)
	}

	err = reloadTags()
	if err != nil {
		log.Debug("failed to get tags", err.Error())
		log.Error("failed to get tags")
		return
	}

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix(DefaultPrompt+" "+Separator),
	)
	p.Run()
}

func completer(in prompt.Document) []prompt.Suggest {
	w := in.TextBeforeCursor()
	if strings.HasPrefix(w, "get ") {
		t := in.GetWordBeforeCursor()
		return prompt.FilterHasPrefix(tagSuggestions, t, true)
	}
	return prompt.FilterHasPrefix(suggestions, w, true)
}

var suggestions = []prompt.Suggest{
	{Text: "help", Description: "help"},
	{Text: "init", Description: "generate and store mnemonic"},
	{Text: "exit", Description: "stop wimp and close cli"},
	{Text: "generate", Description: "generate and store password"},
	{Text: "get", Description: "get password"},
	{Text: "store", Description: "store password"},
	{Text: "export", Description: "export current wimp repository"},
	{Text: "import", Description: "import a previously backed up wimp repository"},
}

var tagSuggestions = []prompt.Suggest{}

var passwordMetadata = map[string]PasswordMetaInfo{}

func reloadTags() error {
	tagSuggestions = []prompt.Suggest{}
	comm := passwordManager.GetNode()
	tags, err := comm.Node.ReplManager().GetAllTags()
	if err != nil {
		log.Debug("unable to get all tags", err.Error())
		log.Error("unable to get all tags")
		return err
	}
	for _, v := range tags {
		if strings.HasPrefix(v, passwordPrefix) {
			metatag := strings.Replace(v, passwordPrefix, passwordMetaPrefix, 1)
			metaReader, _, err := comm.Node.Get(comm.Context, metatag)
			if err != nil {
				log.Debug("get metadata failed", err.Error())
				log.Error("get metadata failed")
				return err
			}
			metadata := bytes.NewBuffer(nil)
			_, err = io.Copy(metadata, metaReader)
			if err != nil {
				log.Debug("metadata read failed", err.Error())
				log.Error("metadata read failed")
				return err
			}
			m := &PasswordMetaInfo{}
			err = json.Unmarshal(metadata.Bytes(), m)
			if err != nil {
				log.Debug("metadata unmarshal failed", err.Error())
				log.Error("mnemonic unmarshal failed")
				return err
			}
			passwordMetadata[metatag] = *m
			tagSuggestions = append(tagSuggestions, prompt.Suggest{Text: v, Description: m.Description})
		}
	}
	return nil
}

func executor(in string) {
	in = strings.TrimSpace(in)
	blocks := strings.Split(in, " ")

	comm := passwordManager.GetNode()
	node := comm.Node
	acc := passwordManager.GetAccount()

	if !passwordManager.IsInitialised() && blocks[0] != "init" && blocks[0] != "exit" {
		fmt.Println("secret is not initialised, please run \"init\"")
		return
	}

	switch blocks[0] {
	case "exit":
		fmt.Println("exiting")
		os.Exit(1)
	case "get":
		if len(blocks) < 2 {
			log.Debug("nothing to get")
			log.Error("nothing to get")
			return
		}
		tag := blocks[len(blocks)-1]
		passPrompt := promptui.Prompt{
			Label: "Master Password ",
			Mask:  '*',
		}
		masterPassword, _ := passPrompt.Run()

		if !acc.VerifyMasterPassword(masterPassword) {
			fmt.Println("Wrong master password")
			return
		}

		// check if mnemonic already exists
		r, _, err := node.Get(comm.Context, tag)
		if err != nil {
			log.Debug("get : unable to get tag", tag, err.Error())
			log.Error("get : unable to get tag", tag)
			return
		}
		buf := bytes.NewBuffer(nil)
		_, err = io.Copy(buf, r)
		if err != nil {
			log.Debug("get : unable to read tag", tag, err.Error())
			log.Error("get : unable to read tag", tag)
			return
		}
		password, err := acc.DecryptContent(masterPassword, buf.String())
		if err != nil {
			log.Debug("get : unable to decrypt password", tag, err.Error())
			log.Error("get : unable to decrypt password", tag)
			return
		}
		metatag := strings.Replace(tag, passwordPrefix, passwordMetaPrefix, 1)
		m := passwordMetadata[metatag]
		fmt.Println("=============== Details ==========================")
		fmt.Printf("Domain : %s\n", m.Domain)
		fmt.Printf("Username : %s\n", m.Username)
		fmt.Printf("Description : %s\n", m.Description)
		fmt.Println("=============== Details ==========================")
		fmt.Println("Password has been copied to clipboard")
		//passwordPrompt := promptui.Prompt{
		//	Label: password,
		//	Templates: &promptui.PromptTemplates{
		//		Prompt:          "{{ . | bold }}",
		//		Confirm:         "{{ . | bold }}",
		//		Valid:           "{{ . | bold }}",
		//		Invalid:         "{{ . | bold }}",
		//		Success:         "{{ . | bold }}",
		//		ValidationError: "{{ . | bold }}",
		//		FuncMap:         nil,
		//	},
		//	HideEntered: true,
		//}
		//_, _ = passwordPrompt.Run()

		clipboard.Write(clipboard.FmtText, []byte(password))
	case "init":
		// check if mnemonic already exists
		_, _, err := node.Get(comm.Context, mnemonicTag)
		if passwordManager.IsInitialised() {
			fmt.Println("secret is already initialised")
			log.Debug("init : repository already initialised")
			log.Error("init : repository already initialised")
			return
		}

		// prompt for password
		passPrompt := promptui.Prompt{
			Label: "Master Password ",
			Mask:  '*',
		}
		password, _ := passPrompt.Run()
		
		// Generate Mnemonic
		mnemonic, encryptedMessage, err := acc.CreateMnemonic(password)
		if err != nil {
			log.Debug("mnemonic creation failed", err.Error())
			log.Error("mnemonic creation failed")
			return
		}

		// Store
		info := &store.Info{
			Tag:         "/mnemonic",
			Type:        "text",
			Name:        "mnemonic",
			IsEncrypted: false,
			Size:        int64(len(encryptedMessage[:])),
		}
		_, err = node.Add(comm.Context, bytes.NewReader([]byte(encryptedMessage)), info)
		if err != nil {
			log.Debug("mnemonic store failed", err.Error())
			log.Error("mnemonic store failed")
			return
		}

		// display information
		fmt.Println("Secure password account created")
		fmt.Println("Please store the following 12 words safely")
		fmt.Println("if you loose this, you cannot recover the data")
		fmt.Println("=============== Mnemonic ==========================")
		fmt.Println(mnemonic)
		fmt.Println("=============== Mnemonic ==========================")
		return
	case "generate":
		lengthPrompt := promptui.Prompt{
			Label: "Password Length ",
		}
		lengthString, _ := lengthPrompt.Run()
		length, err := strconv.Atoi(lengthString)
		if err != nil {
			log.Debug("unable to parse password length", err.Error())
			log.Error("unable to parse password length")
			return
		}
		// prompt for Digit
		digitCountPrompt := promptui.Prompt{
			Label: "Number of required digits ",
		}
		digitCountString, _ := digitCountPrompt.Run()
		digitCount, err := strconv.Atoi(digitCountString)
		if err != nil {
			log.Debug("unable to parse digit count", err.Error())
			log.Error("unable to parse digit count")
			return
		}
		// prompt for symbol
		symbolCountPrompt := promptui.Prompt{
			Label: "Number of required symbols ",
		}
		symbolCountString, _ := symbolCountPrompt.Run()
		symbolCount, err := strconv.Atoi(symbolCountString)
		if err != nil {
			log.Debug("unable to parse symbol count", err.Error())
			log.Error("unable to parse symbol count")
			return
		}
		// prompt for uppercase
		uppercasePrompt := promptui.Prompt{
			Label:     "Should contain Uppercase ",
			IsConfirm: true,
		}
		uppercase, _ := uppercasePrompt.Run()
		uppercaseBool := false
		switch strings.ToLower(uppercase) {
		case "y", "yes":
			uppercaseBool = false
		case "n", "no":
			uppercaseBool = true
		default:
			fmt.Println("unknown choice, considering \"yes\"")
		}

	regenerate:
		password, err := generator.Generate(length, digitCount, symbolCount, uppercaseBool, false)
		if err != nil {
			log.Debug("unable to generate password", err.Error())
			log.Error("unable to generate password")
			return
		}
	regeneratePrompt:
		regenPrompt := promptui.Prompt{
			Label:       fmt.Sprintf("New Password is %s Do you want to choose the above password ? ", password),
			HideEntered: true,
		}
		regenerate, _ := regenPrompt.Run()
		switch strings.ToLower(regenerate) {
		case "y", "yes":

		case "n", "no":
			goto regenerate
		default:
			fmt.Println("unknown choice")
			goto regeneratePrompt
		}
		// prompt for domain
		domainPrompt := promptui.Prompt{
			Label: "Please enter domain name ",
		}
		domain, _ := domainPrompt.Run()
		// prompt for username
		userPrompt := promptui.Prompt{
			Label: "Please enter username ",
		}
		username, _ := userPrompt.Run()
		// prompt for description
		descPrompt := promptui.Prompt{
			Label: "Please enter additional description ",
		}
		desc, _ := descPrompt.Run()

		// show details with generated password
		meta := &PasswordMetaInfo{
			Domain:      domain,
			Username:    username,
			Description: desc,
		}
		fmt.Println("=============== Details ==========================")
		fmt.Printf("Domain : %s\n", domain)
		fmt.Printf("Username : %s\n", username)
		fmt.Printf("Description : %s\n", desc)
		fmt.Println("=============== Details ==========================")

		confirmPrompt := promptui.Prompt{
			Label:     "Do you want to save this ",
			IsConfirm: true,
		}
		confirm, _ := confirmPrompt.Run()
		switch strings.ToLower(confirm) {
		case "y", "yes":
			// encrypt and save
			fmt.Println("saving")
			encryptionPasswordPrompt := promptui.Prompt{
				Label: "Master Password ",
				Mask:  '*',
			}
			
			masterPassword, _ := encryptionPasswordPrompt.Run()
			if !acc.VerifyMasterPassword(masterPassword) {
				fmt.Println("wrong master password")
				return
			}
			
			encryptedPassword, err := acc.EncryptContent(masterPassword, password)
			if err != nil {
				log.Debug("password encryption failed", err.Error())
				log.Error("password encryption failed")
				return
			}
			info := &store.Info{
				Tag:         fmt.Sprintf("%s%s/%s", passwordPrefix, domain, username),
				Type:        "text",
				Name:        fmt.Sprintf("/%s/%s", domain, username),
				IsEncrypted: true,
				Size:        int64(len(encryptedPassword[:])),
			}
			buf := bytes.NewReader([]byte(encryptedPassword))
			_, err = node.Add(comm.Context, buf, info)
			if err != nil {
				log.Debug("password store failed", err.Error())
				log.Error("password store failed")
				return
			}
			metaBytes, err := json.Marshal(meta)
			if err != nil {
				log.Debug("failed marshalling meta", err.Error())
				log.Error("failed marshalling meta")
				return
			}
			metaInfo := &store.Info{
				Tag:         fmt.Sprintf("%s%s/%s", passwordMetaPrefix, domain, username),
				Type:        "text",
				Name:        fmt.Sprintf("/%s/%s", domain, username),
				IsEncrypted: false,
				Size:        int64(len(metaBytes)),
			}
			metaBuf := bytes.NewReader(metaBytes)
			_, err = node.Add(comm.Context, metaBuf, metaInfo)
			if err != nil {
				log.Debug("password metadata store failed", err.Error())
				log.Error("password metadata store failed")
				return
			}
			err = reloadTags()
			if err != nil {
				log.Debug("failed to reload tags", err.Error())
				log.Error("failed to reload tags")
				return
			}
		case "n", "no":
			fmt.Println("going empty handed")
		default:
		}

	case "new":
		passwordPrompt := promptui.Prompt{
			Label: "Password ",
			Mask:  '*',
		}
		password, _ := passwordPrompt.Run()
		confirmPasswordPrompt := promptui.Prompt{
			Label: "Confirm Password ",
			Mask:  '*',
		}
		confirmPassword, _ := confirmPasswordPrompt.Run()
		if password != confirmPassword {
			fmt.Println("Please type password correctly")
			return
		}

		// prompt for domain
		domainPrompt := promptui.Prompt{
			Label: "Please enter domain name ",
		}
		domain, _ := domainPrompt.Run()
		// prompt for username
		userPrompt := promptui.Prompt{
			Label: "Please enter username ",
		}
		username, _ := userPrompt.Run()
		// prompt for description
		descPrompt := promptui.Prompt{
			Label: "Please enter additional description ",
		}
		desc, _ := descPrompt.Run()

		// show details with generated password
		meta := &PasswordMetaInfo{
			Domain:      domain,
			Username:    username,
			Description: desc,
		}
		fmt.Println("=============== Details ==========================")
		fmt.Printf("Domain : %s\n", domain)
		fmt.Printf("Username : %s\n", username)
		fmt.Printf("Description : %s\n", desc)
		fmt.Println("=============== Details ==========================")

		confirmPrompt := promptui.Prompt{
			Label:     "Do you want to save this ",
			IsConfirm: true,
		}
		confirm, _ := confirmPrompt.Run()
		switch strings.ToLower(confirm) {
		case "y", "yes":
			// encrypt and save
			fmt.Println("saving")
			encryptionPasswordPrompt := promptui.Prompt{
				Label: "Master Password ",
				Mask:  '*',
			}
			masterPassword, _ := encryptionPasswordPrompt.Run()

			if !acc.VerifyMasterPassword(masterPassword) {
				fmt.Println("wrong master password")
				return
			}
			
			encryptedPassword, err := acc.EncryptContent(masterPassword, password)
			if err != nil {
				log.Debug("password encryption failed", err.Error())
				log.Error("password encryption failed")
				return
			}
			info := &store.Info{
				Tag:         fmt.Sprintf("%s%s/%s", passwordPrefix, domain, username),
				Type:        "text",
				Name:        fmt.Sprintf("/%s/%s", domain, username),
				IsEncrypted: true,
				Size:        int64(len(encryptedPassword[:])),
			}
			buf := bytes.NewReader([]byte(encryptedPassword))
			_, err = node.Add(comm.Context, buf, info)
			if err != nil {
				log.Debug("password store failed", err.Error())
				log.Error("password store failed")
				return
			}
			metaBytes, err := json.Marshal(meta)
			if err != nil {
				log.Debug("failed marshalling meta", err.Error())
				log.Error("failed marshalling meta")
				return
			}
			metaInfo := &store.Info{
				Tag:         fmt.Sprintf("%s%s/%s", passwordMetaPrefix, domain, username),
				Type:        "text",
				Name:        fmt.Sprintf("/%s/%s", domain, username),
				IsEncrypted: false,
				Size:        int64(len(metaBytes)),
			}
			metaBuf := bytes.NewReader(metaBytes)
			_, err = node.Add(comm.Context, metaBuf, metaInfo)
			if err != nil {
				log.Debug("password metadata store failed", err.Error())
				log.Error("password metadata store failed")
				return
			}
			err = reloadTags()
			if err != nil {
				log.Debug("failed to reload tags", err.Error())
				log.Error("failed to reload tags")
				return
			}
		case "n", "no":
			fmt.Println("going empty handed")
		default:
		}
		return
	case "import":
		if len(blocks) < 2 {
			fmt.Println("kdbx path not specified")
			return
		}
		kdbx := blocks[1]
		// check file stat
		_, err := os.Stat(kdbx)
		if err != nil {
			log.Debug("unable to read kdbx file", err.Error())
			log.Error("unable to read kdbx file")
			return
		}
		file, err := os.Open(kdbx)
		if err != nil {
			log.Debug("unable to read kdbx file", err.Error())
			log.Error("unable to read kdbx file")
			return
		}

		passwordPrompt := promptui.Prompt{
			Label: "KDBX Credential Password ",
			Mask:  '*',
		}
		password, _ := passwordPrompt.Run()

		db := gokeepasslib.NewDatabase()
		db.Credentials = gokeepasslib.NewPasswordCredentials(password)
		err = gokeepasslib.NewDecoder(file).Decode(db)
		if err != nil {
			log.Debug("failed to decode kdbx", err.Error())
			log.Error("failed to decode kdbx")
			return
		}

		err = db.UnlockProtectedEntries()
		if err != nil {
			log.Debug("failed to unlock kdbx", err.Error())
			log.Error("failed to unlock kdbx")
			return
		}
		encryptionPasswordPrompt := promptui.Prompt{
			Label: "Master Password ",
			Mask:  '*',
		}
		masterPassword, _ := encryptionPasswordPrompt.Run()
		
		if !acc.VerifyMasterPassword(masterPassword) {
			fmt.Println("wrong master password")
			return
		}
		
		for _, v := range db.Content.Root.Groups[0].Entries {
			domain := v.GetContent("URL")
			username := v.GetContent("UserName")
			desc := v.GetContent("Notes")
			meta := &PasswordMetaInfo{
				Domain:      domain,
				Username:    username,
				Description: desc,
			}
			fmt.Printf("saving %s for %s on %s", v.GetTitle(), username, domain)
			encryptedPassword, err := acc.EncryptContent(masterPassword, v.GetPassword())
			if err != nil {
				log.Debug("password encryption failed", err.Error())
				log.Error("password encryption failed")
				return
			}
			info := &store.Info{
				Tag:         fmt.Sprintf("%s%s/%s", passwordPrefix, domain, username),
				Type:        "text",
				Name:        fmt.Sprintf("/%s/%s", domain, username),
				IsEncrypted: true,
				Size:        int64(len(encryptedPassword[:])),
			}
			buf := bytes.NewReader([]byte(encryptedPassword))
			_, err = node.Add(comm.Context, buf, info)
			if err != nil {
				log.Debug("password store failed", err.Error())
				log.Error("password store failed")
				return
			}
			metaBytes, err := json.Marshal(meta)
			if err != nil {
				log.Debug("failed marshalling meta", err.Error())
				log.Error("failed marshalling meta")
				return
			}
			metaInfo := &store.Info{
				Tag:         fmt.Sprintf("%s%s/%s", passwordMetaPrefix, domain, username),
				Type:        "text",
				Name:        fmt.Sprintf("/%s/%s", domain, username),
				IsEncrypted: false,
				Size:        int64(len(metaBytes)),
			}
			metaBuf := bytes.NewReader(metaBytes)
			_, err = node.Add(comm.Context, metaBuf, metaInfo)
			if err != nil {
				log.Debug("password metadata store failed", err.Error())
				log.Error("password metadata store failed")
				return
			}
		}
		err = reloadTags()
		if err != nil {
			log.Debug("failed to reload tags", err.Error())
			log.Error("failed to reload tags")
			return
		}
	case "export":
		if len(blocks) < 2 {
			fmt.Println("kdbx path not specified")
			return
		}
		kdbx := blocks[1]
		// check file stat
		_, err := os.Stat(kdbx)
		if err == nil {
			log.Debug("file already exists")
			log.Error("file already exists")
			return
		}
		file, err := os.Create(kdbx)
		if err != nil {
			log.Debug("unable to create kdbx file", err.Error())
			log.Error("unable to create kdbx file")
			return
		}

		passwordPrompt := promptui.Prompt{
			Label: "KDBX Credential Password ",
			Mask:  '*',
		}
		kdbxPassword, _ := passwordPrompt.Run()
		encryptionPasswordPrompt := promptui.Prompt{
			Label: "Master Password ",
			Mask:  '*',
		}
		masterPassword, _ := encryptionPasswordPrompt.Run()

		if !acc.VerifyMasterPassword(masterPassword) {
			fmt.Println("wrong master password")
			return
		}

		tags, err := comm.Node.ReplManager().GetAllTags()
		if err != nil {
			log.Debug("unable to get all tags", err.Error())
			log.Error("unable to get all tags")
			return
		}

		// create root group
		rootGroup := gokeepasslib.NewGroup()
		rootGroup.Name = "root group"

		for _, tag := range tags {
			if strings.HasPrefix(tag, passwordPrefix) {
				// check if mnemonic already exists
				r, _, err := node.Get(comm.Context, tag)
				if err != nil {
					log.Debug("get : unable to get tag", tag, err.Error())
					log.Error("get : unable to get tag", tag)
					return
				}
				buf := bytes.NewBuffer(nil)
				_, err = io.Copy(buf, r)
				if err != nil {
					log.Debug("get : unable to read tag", tag, err.Error())
					log.Error("get : unable to read tag", tag)
					return
				}
				entryPassword, err := acc.DecryptContent(masterPassword, buf.String())
				if err != nil {
					log.Debug("get : unable to decrypt password", tag, err.Error())
					log.Error("get : unable to decrypt password", tag)
					return
				}
				metatag := strings.Replace(tag, passwordPrefix, passwordMetaPrefix, 1)
				m := passwordMetadata[metatag]

				entry := gokeepasslib.NewEntry()
				entry.Values = append(entry.Values, mkValue("Title", tag))
				entry.Values = append(entry.Values, mkValue("UserName", m.Domain))
				entry.Values = append(entry.Values, mkProtectedValue("Password", entryPassword))
				entry.Values = append(entry.Values, mkValue("Notes", m.Description))

				rootGroup.Entries = append(rootGroup.Entries, entry)
			}
		}


		db := &gokeepasslib.Database{
			Header:      gokeepasslib.NewHeader(),
			Credentials: gokeepasslib.NewPasswordCredentials(kdbxPassword),
			Content: &gokeepasslib.DBContent{
				Meta: gokeepasslib.NewMetaData(),
				Root: &gokeepasslib.RootData{
					Groups: []gokeepasslib.Group{rootGroup},
				},
			},
		}

		// Lock entries using stream cipher
		err = db.LockProtectedEntries()
		if err != nil {
			log.Debug("failed to lock kdbx", err.Error())
			log.Error("failed to lock kdbx")
			return
		}

		// and encode it into the file
		keepassEncoder := gokeepasslib.NewEncoder(file)
		if err := keepassEncoder.Encode(db); err != nil {
			log.Debug("failed to encode kdbx", err.Error())
			log.Error("failed to encode kdbx")
			return
		}
		case "n", "no":
			fmt.Println("going empty handed")
		default:
	}
	return
}

func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(true)},
	}
}
