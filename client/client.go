package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	encKey      []byte
	macKey      []byte
	PKEEncKey   userlib.PKEEncKey   //RSA public used to encrypt with userlib.PKEEnc
	PKEDecKey   userlib.PKEDecKey   //RSA private used to decrypt with userlib.PKEDec
	DSSignKey   userlib.DSSignKey   //private signing key with userlib.DSSign - outputs a signature byte array
	DSVerifyKey userlib.DSVerifyKey //public verify key with userlib.DSVerify

	LockBoxMap map[string]uuid.UUID //for each reciipient, there is a Lockbox UUID for a struct that contains FileKey used to encrypt FileStruct/FileContent

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" || password == "" {
		return nil, errors.New("please provide a username and password")
	}
	var userdata User
	userdata.Username = username
	userdata.LockBoxMap = make(map[string]uuid.UUID)

	//create uuid username and put in datastore
	hashed_username := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hashed_username[:16])
	if err != nil {
		return nil, errors.New("invalid username")
	}

	//make sure this user is first time user
	_, ok := userlib.DatastoreGet(usernameUUID)
	if ok {
		return nil, errors.New("username already exists")
	}

	//since user is first timer, generate keys w password
	user_encKey, user_macKey, err := MakeUserKeys(username, password)
	if err != nil {
		return nil, err
	}
	userdata.encKey = user_encKey
	userdata.macKey = user_macKey

	pubEncKey, privDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.PKEEncKey = pubEncKey
	userdata.PKEDecKey = privDecKey

	privSignKey, pubVerKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.DSSignKey = privSignKey
	userdata.DSVerifyKey = pubVerKey

	//user struct created, now encrypt
	plaintext, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	encryptedStruct := userlib.SymEnc(user_encKey[:16], iv, plaintext) //encrypting the user struct

	//create the HMAC tag with macKey
	tag, err := userlib.HMACEval(user_macKey[:16], encryptedStruct)
	if err != nil {
		return nil, err
	}
	datastore_UserValue := append(encryptedStruct, tag...) //final value that will be stored in DataStore

	userlib.DatastoreSet(usernameUUID, datastore_UserValue)

	//add public keys to KeyStore for others to use when creating invitations
	err = userlib.KeystoreSet(username+"Encrypt", pubEncKey)
	if err != nil {
		return nil, err //*ASK IN OFFICE HOURS* if keystore errors (being modified) do you delete the entire user from datastore as precaution?
	}
	err = userlib.KeystoreSet(username+"Verify", pubVerKey)
	if err != nil {
		return nil, err
	}

	return &userdata, nil

}

func GetUser(username string, password string) (userdataptr *User, err error) {
	if username == "" || password == "" {
		return nil, errors.New("please provide a username and password")
	}
	var userdata User
	//generate deterministic uuid
	hashed_username := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hashed_username[:16])
	if err != nil {
		return nil, errors.New("username invalid")
	}

	//get from datastore
	encryptedStruct, ok := userlib.DatastoreGet(usernameUUID)
	if !ok {
		return nil, errors.New("user does not exist")
	}
	if len(encryptedStruct) < userlib.HashSizeBytes {
		return nil, errors.New("corrupted ciphertext")
	}

	user_encKey, user_macKey, err := MakeUserKeys(username, password)
	if err != nil {
		return nil, err
	}
	userdata.encKey = user_encKey
	userdata.macKey = user_macKey

	ciphertext := encryptedStruct[:(len(encryptedStruct) - userlib.HashSizeBytes)] //extract ciphertext from combined HMAC
	tag := encryptedStruct[(len(encryptedStruct) - userlib.HashSizeBytes):]

	expectedTag, err := userlib.HMACEval(user_macKey[:16], ciphertext)
	if err != nil {
		return nil, err
	}
	//verify HMAC before decrypting
	tagMatch := userlib.HMACEqual(expectedTag, tag)
	if !tagMatch {
		return nil, errors.New("BAD USER GO AWAY")
	}
	//password is correct
	plaintext := userlib.SymDec(user_encKey[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return nil, err
	}

	userdataptr = &userdata

	return userdataptr, nil
}

type FileContents struct {
	Content []byte
	Next    userlib.UUID
}
type FileStart struct {
	FileOwner string
	Head      userlib.UUID
	Tail      userlib.UUID
}
type LockBox struct {
	FileEncKey []byte
	FileMacKey []byte
	FileUUID   uuid.UUID
}
type Access struct {
	LockBox       uuid.UUID
	LockBoxEncKey []byte //random key generated in storeFile , used to encrypt LockBox which has FileKey
	LockBoxMacKey []byte
} //encrypted with personal

func (userdata *User) StoreFile(filename string, content []byte) (err error) { //generate uuid of file, datastore set uuid and file starter struct
	if filename == "" {
		return errors.New("please provide a valid filename and contents")
	}

	//UUID of FILENAME + username deterministically for the FileStart which will link to all content blocks
	fileStartUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}

	//first block of content created as a struct
	var fc FileContents
	fileContentUUID := uuid.New()
	if err != nil {
		return err
	}
	fc.Content = content
	fc.Next = fileStartUUID

	//filename's FileStart struct created, points to first and last fileContents blocks
	var starter FileStart
	starter.FileOwner = userdata.Username
	starter.Head = fileContentUUID
	starter.Tail = fileContentUUID

	var lockBox LockBox //initialize a lockbox for this filename
	var access Access
	accessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "access" + userdata.Username))[:16])

	lockBoxUUID := uuid.New()
	if err != nil {
		return err
	}

	//generate a random Key (fileKey) + add to Lockbox struct and encrypt FileContents
	fileKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	fileMACKey, err := userlib.HashKDF(fileKey, []byte("mac"))
	if err != nil {
		return err
	}
	lockBox.FileEncKey = fileKey //store fileKey in the lockbox to be accessed later in load file and sharing files
	lockBox.FileMacKey = fileMACKey
	lockBox.FileUUID = fileStartUUID

	//generate a lockbox Key which encrypts the LockBox and is stored in Access struct
	lockBoxKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	lockBoxMACKey, err := userlib.HashKDF(lockBoxKey, []byte("mac"))
	if err != nil {
		return err
	}
	access.LockBoxEncKey = lockBoxKey
	access.LockBoxMacKey = lockBoxMACKey

	//encrypt fileStart
	fileStartCipher, err := SymEncryption(starter, fileKey, fileMACKey)
	if err != nil {
		return err
	}

	// encrypt FileContents with same process above
	fileContentCipher, err := SymEncryption(fc, fileKey, fileMACKey)
	if err != nil {
		return err
	}

	//encrypt lockbox
	lockBoxCipher, err := SymEncryption(lockBox, lockBoxKey, lockBoxMACKey)
	if err != nil {
		return err
	}
	//encrypt Access struct
	accessCipher, err := SymEncryption(access, userdata.encKey, userdata.macKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStartUUID, fileStartCipher)     //add filename's UUID + fileStartenc to datastore
	userlib.DatastoreSet(fileContentUUID, fileContentCipher) //add file content's UUID + file Content enc to datastore
	userlib.DatastoreSet(lockBoxUUID, lockBoxCipher)         //add lockbox's UUID + lockbox struct to datastore
	userlib.DatastoreSet(accessUUID, accessCipher)           //add access's UUID + access struct to datastore

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16]) //fileStart UUID
	if err != nil {
		return err
	}
	ciphertext, ok := userlib.DatastoreGet(fileUUID) //encrypted+tag marshaled fileStart struct
	if !ok {
		return errors.New(filename + "file does not exist")
	}

	var accessStruct Access
	access_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + "access" + userdata.Username))[:16])
	if err != nil {
		return err
	}
	accessCipher, ok := userlib.DatastoreGet(access_uuid)
	if !ok {
		return errors.New("access struct does not exist")
	}
	err = SymDecryption(accessCipher, userdata.encKey, userdata.macKey, &accessStruct)
	if err != nil {
		return err
	}
	lockboxUUID := accessStruct.LockBox
	lockboxEncKey := accessStruct.LockBoxEncKey
	lockboxMacKey := accessStruct.LockBoxMacKey

	// find lockbox and decrypt w lockboxKey to get fileKey
	var lockBox LockBox
	lockBoxCipher, ok := userlib.DatastoreGet(lockboxUUID)
	if !ok {
		return errors.New("lock box does not exist")
	}
	err = SymDecryption(lockBoxCipher, lockboxEncKey, lockboxMacKey, &lockBox)
	if err != nil {
		return err
	}
	ogEncFileKey := lockBox.FileEncKey
	ogMacFileKey := lockBox.FileMacKey

	//file exists and we have fileKey so need to decrypt fileStart struct
	var fileStartCopy FileStart
	err = SymDecryption(ciphertext, ogEncFileKey, ogMacFileKey, &fileStartCopy)
	if err != nil {
		return err
	}
	currTailOfFileUUID := fileStartCopy.Tail                          //last file content
	currFileEndCipher, ok := userlib.DatastoreGet(currTailOfFileUUID) //encrypted+tag marshaled fileContent struct that is the end of the file
	if !ok {
		return errors.New("file does not exist")
	}
	var currFileEndCopy FileContents
	err = SymDecryption(currFileEndCipher, ogEncFileKey, ogMacFileKey, &currFileEndCopy) //currFileEndCopy now has the curr last fileContent block
	if err != nil {
		return err
	}

	newFileContentUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + string(content)))[:16])
	var newfileBlock FileContents
	if err != nil {
		return err
	}
	newfileBlock.Content = content
	newfileBlock.Next = fileUUID

	currFileEndCopy.Next = newFileContentUUID //currFileEnd now points to the new appended FileContent block
	fileStartCopy.Tail = newFileContentUUID   // fileStart for this filename Tail pointer = new appended FileContent block

	//re-encryt FileStart and currFileEnd, and encrypt newFileEnd
	fileStartValue, err := SymEncryption(fileStartCopy, ogEncFileKey, ogMacFileKey)
	if err != nil {
		return err
	}
	currFileEndValue, err := SymEncryption(currFileEndCopy, ogEncFileKey, ogMacFileKey)
	if err != nil {
		return err
	}
	newFileEndValue, err := SymEncryption(newfileBlock, ogEncFileKey, ogMacFileKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileUUID, fileStartValue)             //add filename's UUID + fileStartenc to datastore
	userlib.DatastoreSet(currTailOfFileUUID, currFileEndValue) //add file content's UUID + file Content enc to datastore
	userlib.DatastoreSet(newFileContentUUID, newFileEndValue)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var loadedFile []byte
	//check if file exists in datastore, if not error
	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	ciphertext, ok := userlib.DatastoreGet(fileUUID) //encrypted+tag marshaled fileStart struct
	if !ok {
		return nil, errors.New("file does not exist")
	}
	//get access UUID from user map, get from datastore decrypt with private encKey, and store lockbox uuid and key
	var accessStruct Access
	access_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + "access" + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	accessCipher, ok := userlib.DatastoreGet(access_uuid)
	if !ok {
		return nil, errors.New("content does not exist")
	}
	err = SymDecryption(accessCipher, userdata.encKey, userdata.macKey, &accessStruct)
	if err != nil {
		return nil, err
	}
	lockboxUUID := accessStruct.LockBox
	lockboxEncKey := accessStruct.LockBoxEncKey
	lockboxMacKey := accessStruct.LockBoxMacKey

	// find lockbox and decrypt w lockboxKey to get fileKey
	var lockBox LockBox
	lockBoxCipher, ok := userlib.DatastoreGet(lockboxUUID)
	if !ok {
		return nil, errors.New("content does not exist")
	}
	err = SymDecryption(lockBoxCipher, lockboxEncKey, lockboxMacKey, &lockBox)
	if err != nil {
		return nil, err
	}
	ogEncFileKey := lockBox.FileEncKey
	ogMacFileKey := lockBox.FileMacKey

	//file exists and we have fileKey so need to decrypt fileStart struct
	var fileStartCopy FileStart
	err = SymDecryption(ciphertext, ogEncFileKey, ogMacFileKey, &fileStartCopy)
	if err != nil {
		return nil, err
	}

	//only one FileContent (loading file after one call to store file)
	if fileStartCopy.Head == fileStartCopy.Tail {
		var fileContentCopy FileContents
		fileContentcipher, ok := userlib.DatastoreGet(fileStartCopy.Head)
		if !ok {
			return nil, errors.New("content does not exist")
		}
		err = SymDecryption(fileContentcipher, ogEncFileKey, ogMacFileKey, &fileContentCopy)
		if err != nil {
			return nil, err
		}
		loadedFile = fileContentCopy.Content
		return loadedFile, nil
	}

	//multiple file contents exist, so loop through nexts until next == tail of fileStart -> decrypt and append content to loadedFile
	currUUID := fileStartCopy.Head
	for currUUID != fileUUID {
		var fileContentCopy FileContents
		currContentcipher, ok := userlib.DatastoreGet(currUUID)
		if !ok {
			return nil, errors.New("content does not exist")
		}
		err = SymDecryption(currContentcipher, ogEncFileKey, ogMacFileKey, &fileContentCopy)
		if err != nil {
			return nil, err
		}
		loadedFile = append(loadedFile, fileContentCopy.Content...)
		currUUID = fileContentCopy.Next
	}

	return loadedFile, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

// Helper Functions
func MakeUserKeys(username string, password string) (encKey []byte, macKey []byte, err error) {
	rootKey := userlib.Argon2Key([]byte(password), []byte(username), 32)

	user_encKey, err := userlib.HashKDF(rootKey[:16], []byte("encryption"))
	if err != nil {
		return nil, nil, err
	}
	user_macKey, err := userlib.HashKDF(rootKey[:16], []byte("MAC"))
	if err != nil {
		return nil, nil, err
	}

	return user_encKey, user_macKey, nil
}

func SymEncryption(v any, encKey []byte, macKey []byte) (ciphertext []byte, err error) {
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)

	byteArr, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	cipher := userlib.SymEnc(encKey[:16], iv, byteArr)
	tag, err := userlib.HMACEval(macKey[:16], cipher)
	if err != nil {
		return nil, err
	}
	ciphertextMac := append(cipher, tag...)
	return ciphertextMac, nil
}

func SymDecryption(ciphertextMac []byte, encKey []byte, macKey []byte, v any) (err error) {
	ciphertext := ciphertextMac[:(len(ciphertextMac) - userlib.HashSizeBytes)] //extract ciphertext from combined HMAC
	tag := ciphertextMac[(len(ciphertextMac) - userlib.HashSizeBytes):]

	expectedTag, err := userlib.HMACEval(macKey[:16], ciphertext)
	if err != nil {
		return err
	}
	//verify HMAC before decrypting
	tagMatch := userlib.HMACEqual(expectedTag, tag)
	if !tagMatch {
		return errors.New("BAD USER GO AWAY")
	}
	//password is correct
	newPlaintext := userlib.SymDec(encKey[:16], ciphertext)
	err = json.Unmarshal(newPlaintext, v)
	if err != nil {
		return err
	}

	return err
}
