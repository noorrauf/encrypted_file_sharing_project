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

	EncKey      []byte              `json:"-"`
	MacKey      []byte              `json:"-"`
	PKEEncKey   userlib.PKEEncKey   //RSA public used to encrypt with userlib.PKEEnc
	PKEDecKey   userlib.PKEDecKey   //RSA private used to decrypt with userlib.PKEDec
	DSSignKey   userlib.DSSignKey   //private signing key with userlib.DSSign - outputs a signature byte array
	DSVerifyKey userlib.DSVerifyKey //public verify key with userlib.DSVerify

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
	userdata.EncKey = user_encKey
	userdata.MacKey = user_macKey

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
		return nil, err
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
	userdata.EncKey = user_encKey
	userdata.MacKey = user_macKey

	ciphertext := encryptedStruct[:(len(encryptedStruct) - userlib.HashSizeBytes)] //extract ciphertext from combined HMAC
	tag := encryptedStruct[(len(encryptedStruct) - userlib.HashSizeBytes):]

	expectedTag, err := userlib.HMACEval(user_macKey[:16], ciphertext)
	if err != nil {
		return nil, err
	}

	//verify HMAC before decrypting
	tagMatch := userlib.HMACEqual(expectedTag, tag)
	if !tagMatch {
		return nil, errors.New("you are not a user, GO AWAY")
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

type Map struct {
	LockBoxUUIDMap map[string]uuid.UUID //for each reciipient, there is a Lockbox UUID for a struct that contains FileKey/FileUUIDn used to encrypt FileStruct/FileContent
	LockBoxEncMap  map[string][]byte    //for each reciipient, there is a lockBox encryption Key for a struct that contains FileKey/FileUUIDn used to encrypt FileStruct/FileContent
	LockBoxMacMap  map[string][]byte    //for each reciipient, there is a Lockbox mac key for a struct that contains FileKey/FileUUIDn used to encrypt FileStruct/FileContent

}
type FileStart struct {
	FileOwner string
	Head      userlib.UUID
	Tail      userlib.UUID
	Map       userlib.UUID
}
type LockBox struct {
	FileEncKey []byte
	FileMacKey []byte
	FileUUID   uuid.UUID
	Revoked    bool
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
	fileStartUUID := uuid.New()

	//first block of content created as a struct
	var fc FileContents
	fileContentUUID := uuid.New()

	fc.Content = content
	fc.Next = uuid.Nil

	//initialize Map struct
	var map_struct Map
	mapUUID := uuid.New()
	map_struct.LockBoxUUIDMap = make(map[string]uuid.UUID)
	map_struct.LockBoxEncMap = make(map[string][]byte)
	map_struct.LockBoxMacMap = make(map[string][]byte)

	//filename's FileStart struct created, points to first and last fileContents blocks
	var starter FileStart
	starter.FileOwner = userdata.Username
	starter.Head = fileContentUUID
	starter.Tail = fileContentUUID
	starter.Map = mapUUID

	var lockBox LockBox //initialize a lockbox for this filename
	var access Access   // initialize an access struct which has a unique uuid bc each filename is uniquely created by this user
	accessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	lockBoxUUID := uuid.New()

	//generate a random Key (fileKey) + add to Lockbox struct and encrypt FileContents
	fileKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	fileMACKey, err := userlib.HashKDF(fileKey, []byte("mac"))
	if err != nil {
		return err
	}
	lockBox.FileEncKey = fileKey //store fileKey in the lockbox to be accessed later in load file and sharing files
	lockBox.FileMacKey = fileMACKey
	lockBox.FileUUID = fileStartUUID
	lockBox.Revoked = false

	//generate a lockbox Key which encrypts the LockBox and is stored in Access struct
	lockBoxKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	lockBoxMACKey, err := userlib.HashKDF(lockBoxKey, []byte("mac"))
	if err != nil {
		return err
	}
	access.LockBoxEncKey = lockBoxKey
	access.LockBoxMacKey = lockBoxMACKey
	access.LockBox = lockBoxUUID

	//encrypt fileStart
	fileStartCipher, err := SymEncryption(starter, fileKey, fileMACKey, userdata.Username)
	if err != nil {
		return err
	}

	// encrypt FileContents with same process above
	fileContentCipher, err := SymEncryption(fc, fileKey, fileMACKey, userdata.Username)
	if err != nil {
		return err
	}

	//encrypt lockbox
	lockBoxCipher, err := SymEncryption(lockBox, lockBoxKey, lockBoxMACKey, userdata.Username)
	if err != nil {
		return err
	}
	//encrypt Access struct
	accessCipher, err := SymEncryption(access, userdata.EncKey, userdata.MacKey, userdata.Username)
	if err != nil {
		return err
	}

	//encrypt Map struct
	mapCipher, err := SymEncryption(map_struct, userdata.EncKey, userdata.MacKey, userdata.Username)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileStartUUID, fileStartCipher)     //add filename's UUID + fileStartenc to datastore
	userlib.DatastoreSet(fileContentUUID, fileContentCipher) //add file content's UUID + file Content enc to datastore
	userlib.DatastoreSet(lockBoxUUID, lockBoxCipher)         //add lockbox's UUID + lockbox struct to datastore
	userlib.DatastoreSet(accessUUID, accessCipher)           //add access's UUID + access struct to datastore
	userlib.DatastoreSet(mapUUID, mapCipher)                 //add map's UUID + map struct to datastore

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	//need to access Access struct which can be found with deterministic UUID and find lockbox information
	var accessStruct Access
	access_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	accessCipher, ok := userlib.DatastoreGet(access_uuid)
	if !ok { //check if file exists in datastore, if not error
		return errors.New("does not exist in datastore")
	}
	err = SymDecryption(accessCipher, userdata.EncKey, userdata.MacKey, &accessStruct, userdata.Username)
	if err != nil {
		return err
	}
	lockboxUUID := accessStruct.LockBox
	lockboxEncKey := accessStruct.LockBoxEncKey
	lockboxMacKey := accessStruct.LockBoxMacKey

	// find lockbox and decrypt w lockboxKey to get fileKey and fileStart UUID
	var lockBox LockBox
	lockBoxCipher, ok := userlib.DatastoreGet(lockboxUUID)
	if !ok {
		return errors.New(filename + "lock box does not exist when appending file")
	}
	err = SymDecryption(lockBoxCipher, lockboxEncKey, lockboxMacKey, &lockBox, userdata.Username)
	if err != nil {
		return err
	}
	ogEncFileKey := lockBox.FileEncKey
	ogMacFileKey := lockBox.FileMacKey
	fileUUID := lockBox.FileUUID //fileStart UUID
	if lockBox.Revoked {
		return errors.New("you are not allowed to access this file")
	}

	ciphertext, ok := userlib.DatastoreGet(fileUUID) //encrypted+tag marshaled fileStart struct
	if !ok {
		return errors.New(filename + " file does not exist")
	}

	//file exists and we have fileKey so need to decrypt fileStart struct
	var fileStartCopy FileStart
	err = SymDecryption(ciphertext, ogEncFileKey, ogMacFileKey, &fileStartCopy, userdata.Username)
	if err != nil {
		return err
	}
	currTailOfFileUUID := fileStartCopy.Tail                          //last file content
	currFileEndCipher, ok := userlib.DatastoreGet(currTailOfFileUUID) //encrypted+tag marshaled fileContent struct that is the end of the file
	if !ok {
		return errors.New("file does not exist")
	}
	var currFileEndCopy FileContents
	err = SymDecryption(currFileEndCipher, ogEncFileKey, ogMacFileKey, &currFileEndCopy, userdata.Username) //currFileEndCopy now has the curr last fileContent block
	if err != nil {
		return err
	}

	//create a new FileContents for this new block being appended
	newFileContentUUID := uuid.New()
	var newfileBlock FileContents

	newfileBlock.Content = content
	newfileBlock.Next = uuid.Nil //points back to the fileStart

	currFileEndCopy.Next = newFileContentUUID //currFileEnd now points to the new appended FileContent block
	fileStartCopy.Tail = newFileContentUUID   // fileStart for this filename Tail pointer = new appended FileContent block

	//re-encryt FileStart and currFileEnd, and encrypt newFileEnd
	fileStartValue, err := SymEncryption(fileStartCopy, ogEncFileKey, ogMacFileKey, userdata.Username)
	if err != nil {
		return err
	}
	currFileEndValue, err := SymEncryption(currFileEndCopy, ogEncFileKey, ogMacFileKey, userdata.Username)
	if err != nil {
		return err
	}
	newFileEndValue, err := SymEncryption(newfileBlock, ogEncFileKey, ogMacFileKey, userdata.Username)
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

	//get access UUID from user map, get from datastore decrypt with private encKey, and store lockbox uuid and key
	var accessStruct Access
	access_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	accessCipher, ok := userlib.DatastoreGet(access_uuid)
	if !ok { //check if file exists in datastore, if not error
		return nil, errors.New("does not exist in datastore")
	}
	err = SymDecryption(accessCipher, userdata.EncKey, userdata.MacKey, &accessStruct, userdata.Username)
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
		return nil, errors.New("lockbox for" + filename + "doesn't exist")
	}
	err = SymDecryption(lockBoxCipher, lockboxEncKey, lockboxMacKey, &lockBox, userdata.Username)
	if err != nil {
		return nil, err
	}
	ogEncFileKey := lockBox.FileEncKey
	ogMacFileKey := lockBox.FileMacKey
	fileUUID := lockBox.FileUUID
	if lockBox.Revoked {
		return nil, errors.New("you are not allowed to access this file")
	}

	ciphertext, ok := userlib.DatastoreGet(fileUUID) //encrypted+tag marshaled fileStart struct
	if !ok {
		return nil, errors.New("file does not exist")
	}

	//file exists and we have fileKey so need to decrypt fileStart struct
	var fileStartCopy FileStart
	err = SymDecryption(ciphertext, ogEncFileKey, ogMacFileKey, &fileStartCopy, userdata.Username)
	if err != nil {
		return nil, err
	}

	//only one FileContent (loading file after one call to store file)
	if fileStartCopy.Head == fileStartCopy.Tail {
		var fileContentCopy FileContents
		fileContentcipher, ok := userlib.DatastoreGet(fileStartCopy.Head)
		if !ok {
			return nil, errors.New("first file content block does not exist")
		}
		err = SymDecryption(fileContentcipher, ogEncFileKey, ogMacFileKey, &fileContentCopy, userdata.Username)
		if err != nil {
			return nil, err
		}
		loadedFile = fileContentCopy.Content
		return loadedFile, nil
	}

	//multiple file contents exist, so loop through nexts until next == tail of fileStart -> decrypt and append content to loadedFile
	currUUID := fileStartCopy.Head
	for currUUID != uuid.Nil {
		var fileContentCopy FileContents
		currContentcipher, ok := userlib.DatastoreGet(currUUID)
		if !ok {
			return nil, errors.New("content does not exist")
		}
		err = SymDecryption(currContentcipher, ogEncFileKey, ogMacFileKey, &fileContentCopy, userdata.Username)
		if err != nil {
			return nil, err
		}
		loadedFile = append(loadedFile, fileContentCopy.Content...)
		currUUID = fileContentCopy.Next
	}

	return loadedFile, nil
}

type Invitation struct {
	LockBoxUUID   uuid.UUID
	LockBoxEncKey []byte
	LockBoxMacKey []byte
	InvOwner      string
	Recipient     string
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//decrypt access struct
	var accessStruct Access
	access_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	accessCipher, ok := userlib.DatastoreGet(access_uuid)
	if !ok { //check if file exists in datastore, if not error
		return uuid.Nil, errors.New("does not exist in datastore")
	}

	err = SymDecryption(accessCipher, userdata.EncKey, userdata.MacKey, &accessStruct, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	lockboxUUID := accessStruct.LockBox
	lockboxEncKey := accessStruct.LockBoxEncKey
	lockboxMacKey := accessStruct.LockBoxMacKey

	//decrypt lockbox
	var lockBox LockBox
	lockBoxCipher, ok := userlib.DatastoreGet(lockboxUUID)
	if !ok {
		return uuid.Nil, errors.New("lockbox for" + filename + "doesn't exist")
	}
	err = SymDecryption(lockBoxCipher, lockboxEncKey, lockboxMacKey, &lockBox, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	ogEncFileKey := lockBox.FileEncKey
	ogMacFileKey := lockBox.FileMacKey
	fileUUID := lockBox.FileUUID

	ciphertext, ok := userlib.DatastoreGet(fileUUID) //encrypted+tag marshaled fileStart struct
	if !ok {
		return uuid.Nil, errors.New("file does not exist")
	}
	//file exists and we have fileKey so need to decrypt fileStart struct
	var fileStartCopy FileStart
	err = SymDecryption(ciphertext, ogEncFileKey, ogMacFileKey, &fileStartCopy, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	//access the Map with the uuid stored in FileStart because user needs to update if they are the owner and sharing cause needed in revoke access
	var fileMap Map
	map_uuid := fileStartCopy.Map
	mapCipher, ok := userlib.DatastoreGet(map_uuid)
	if !ok { //check if map exists in datastore, if not error
		return uuid.Nil, errors.New("map does not exist in datastore")
	}

	//only if user is the owner, then decrypt the map with their keys
	if fileStartCopy.FileOwner == userdata.Username {

		err = SymDecryption(mapCipher, userdata.EncKey, userdata.MacKey, &fileMap, userdata.Username)
		if err != nil {
			return uuid.Nil, err
		}
	}

	var inv Invitation

	if fileStartCopy.FileOwner != userdata.Username { //if non owner is sharing to another person, share a lockbox
		inv.LockBoxUUID = lockboxUUID
		inv.LockBoxEncKey = lockboxEncKey
		inv.LockBoxMacKey = lockboxMacKey
		inv.Recipient = recipientUsername
		inv.InvOwner = userdata.Username

	} else { //meaning user creating inv IS the owner and needs to update their Map so they know the lockbox of the person they directly shared with
		var recipientLockBox LockBox
		recipientLockBox.FileUUID = fileUUID
		recipientLockBox.FileEncKey = ogEncFileKey
		recipientLockBox.FileMacKey = ogMacFileKey
		recipientLockBox.Revoked = false

		recipientLockBoxUUID := uuid.New()
		recipientLockBoxKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
		recipientLockBoxMACKey, err := userlib.HashKDF(recipientLockBoxKey, []byte("mac"))
		if err != nil {
			return uuid.Nil, err
		}
		//encrypt lockbox
		recipientLockBoxCipher, err := SymEncryption(recipientLockBox, recipientLockBoxKey, recipientLockBoxMACKey, userdata.Username)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(recipientLockBoxUUID, recipientLockBoxCipher) //store recipients LockBox in datastore

		//invitation with new LB has been created to send to the other user
		inv.LockBoxUUID = recipientLockBoxUUID
		inv.LockBoxEncKey = recipientLockBoxKey
		inv.LockBoxMacKey = recipientLockBoxMACKey
		inv.Recipient = recipientUsername
		inv.InvOwner = userdata.Username

		//Since user IS THE OWNER, add everything to the maps in the Map Struct for this recipient and Encrypt IN THE IF statement to use only the owners keys (Bob should not be encrypting the map struct, only Alice)
		fileMap.LockBoxUUIDMap[recipientUsername] = recipientLockBoxUUID
		fileMap.LockBoxEncMap[recipientUsername] = recipientLockBoxKey
		fileMap.LockBoxMacMap[recipientUsername] = recipientLockBoxMACKey
		mapCipher, err := SymEncryption(fileMap, userdata.EncKey, userdata.MacKey, userdata.Username)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(map_uuid, mapCipher)

	}
	invUUID := uuid.New()
	symKey := userlib.RandomBytes(userlib.AESKeySizeBytes) //generate symmetric private key

	//Get the public key of recipient to encrypt symKey
	pubKey, ok := userlib.KeystoreGet(recipientUsername + "Encrypt")
	if !ok {
		return uuid.Nil, errors.New("recipient not in Keystore")
	}

	hybridKey, err := userlib.PKEEnc(pubKey, symKey) //using RSA-OAEP to encrypt symKey with public RSA key
	if err != nil {
		return uuid.Nil, err
	}

	byteInv, err := json.Marshal(inv)
	if err != nil {
		return uuid.Nil, err
	}

	cipher_iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	cipherInv := userlib.SymEnc(symKey, cipher_iv, byteInv) //

	combined := append(cipherInv, hybridKey...)                          //encrypted message plus the encrypted key
	signedCipherInv, err := userlib.DSSign(userdata.DSSignKey, combined) //256 byte signature on the encrypted message
	if err != nil {
		return uuid.Nil, err
	}
	storedValue := append(combined, signedCipherInv...) //need to access the msg AND the signature for verification

	userlib.DatastoreSet(invUUID, storedValue)

	return invUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//DatastoreGet invitation struct with invitationPtr
	combined, ok := userlib.DatastoreGet(invitationPtr) //msg + encrypted key + 256 byte sig
	if !ok {
		return errors.New("invitation doesnt exist")
	}
	if len(combined) < 256 {
		return errors.New("invalid invitation data")
	}

	signedMsg := combined[:len(combined)-256]
	signature := combined[(len(combined) - 256):]

	//verify the signature on the cipher invitation
	pubVerificationKey, ok := userlib.KeystoreGet(senderUsername + "Verify")
	if !ok {
		return errors.New("sender doesn't have a Verification Key in Keystore")
	}
	err := userlib.DSVerify(pubVerificationKey, signedMsg, signature)
	if err != nil {
		return errors.New("signature verification failed - INVITATION TAMPERED")
	}

	//signature valid! split the byte arr into struct and symmetric key (16 bytes long)
	cipherInv := signedMsg[:len(signedMsg)-256]
	hybridKey := signedMsg[len(signedMsg)-256:]

	//decrypt hybrid key
	symDecKey, err := userlib.PKEDec(userdata.PKEDecKey, hybridKey)
	if err != nil {
		return errors.New("decryption failed - THIS INVITATION IS NOT FOR YOU")
	}
	var invCopy Invitation

	invitationStructBytes := userlib.SymDec(symDecKey, cipherInv)

	err = json.Unmarshal(invitationStructBytes, &invCopy)
	if err != nil {
		return errors.New("failed to create struct from invitation")
	}
	//recipient user now needs an Access Struct for this file under their filename that will store info of lockbox from invitation struct so they can access the file in the future
	var access Access
	accessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	access.LockBoxEncKey = invCopy.LockBoxEncKey
	access.LockBoxMacKey = invCopy.LockBoxMacKey
	access.LockBox = invCopy.LockBoxUUID

	accessCipher, err := SymEncryption(access, userdata.EncKey, userdata.MacKey, userdata.Username)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(accessUUID, accessCipher)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	//decrypt access struct --> decrypt lockbox struct --> get fileStart
	var accessStruct Access
	access_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	accessCipher, ok := userlib.DatastoreGet(access_uuid)
	if !ok { //check if file exists in datastore, if not error
		return errors.New("does not exist in datastore")
	}
	err = SymDecryption(accessCipher, userdata.EncKey, userdata.MacKey, &accessStruct, userdata.Username)
	if err != nil {
		return err
	}
	lockboxUUID := accessStruct.LockBox //user's lockboxUUID
	lockboxEncKey := accessStruct.LockBoxEncKey
	lockboxMacKey := accessStruct.LockBoxMacKey

	//decrypt lockbox
	var lockBox LockBox
	lockBoxCipher, ok := userlib.DatastoreGet(lockboxUUID)
	if !ok {
		return errors.New("lockbox for" + filename + "doesn't exist")
	}
	err = SymDecryption(lockBoxCipher, lockboxEncKey, lockboxMacKey, &lockBox, userdata.Username)
	if err != nil {
		return err
	}
	ogEncFileKey := lockBox.FileEncKey //original
	ogMacFileKey := lockBox.FileMacKey
	fileStartUUID := lockBox.FileUUID

	ciphertext, ok := userlib.DatastoreGet(fileStartUUID) //encrypted+tag marshaled fileStart struct
	if !ok {
		return errors.New("file does not exist")
	}
	var fileStartCopy FileStart
	err = SymDecryption(ciphertext, ogEncFileKey, ogMacFileKey, &fileStartCopy, userdata.Username)
	if err != nil {
		return err
	}

	newFileStartUUID := uuid.New() //generate a new UUID for this file to revoke from others
	newFileKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	newFileMACKey, err := userlib.HashKDF(newFileKey, []byte("mac"))
	if err != nil {
		return err
	}

	//file start is at fileStartUUID RIGHT NOW, need to move to newFileStartUUID
	newCurrUUID := newFileStartUUID  //where the curr file block will be
	ogNextUUID := fileStartCopy.Head //first file content UUID
	newNextUUID := uuid.New()        //where first file content will placed
	fileStartCopy.Head = newNextUUID

	//loop
	for ogNextUUID != uuid.Nil {
		var contentCopy FileContents
		cipherContent, ok := userlib.DatastoreGet(ogNextUUID)
		if !ok {
			return errors.New("next file content does not exist in datastore")
		}
		err := SymDecryption(cipherContent, ogEncFileKey, ogMacFileKey, &contentCopy, userdata.Username)
		if err != nil {
			return err
		}
		newCurrUUID = newNextUUID      //newCurrUUID = A's new uuid
		ogNextUUID = contentCopy.Next  //where B is currently
		newNextUUID = uuid.New()       //where B will be moved to
		contentCopy.Next = newNextUUID //current block Next pointer now points to B's new uuid

		contentCipher, err := SymEncryption(contentCopy, newFileKey, newFileMACKey, userdata.Username)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(newCurrUUID, contentCipher) //this file block has successfully been moved to a new UUID
	}

	fileStartCopy.Tail = newCurrUUID
	//copyA = unmarshal(decrypt(datastoreGet(ogNext)))
	//newCurrUUID = newNextUUID A's new UUID
	// ogNext = copyA.next --> B
	//newNextUUID = uuid.New()B's new UUID
	// copyA.next = newNextUUID
	//encry A
	// datastoreset(newCurrUUID, enc A)

	//FileStart and FileContents have been moved. Update own lockbox and lockboxes of ppl we want to keep access with newFileKey and newFileStartUUID
	var mapCopy Map
	mapUUID := fileStartCopy.Map
	mapCipher, ok := userlib.DatastoreGet(mapUUID)
	if !ok {
		return errors.New("map not found")
	}

	err = SymDecryption(mapCipher, userdata.EncKey, userdata.MacKey, &mapCopy, userdata.Username)
	if err != nil {
		return err
	}

	recipientToLockboxUUIDMap := mapCopy.LockBoxUUIDMap
	recipientToLockboxEncKeyMap := mapCopy.LockBoxEncMap
	recipientToLockboxMacKeyMap := mapCopy.LockBoxMacMap

	//update own lockbox TODO: reset lockBox at lockboxUUID
	lockBox.FileUUID = newFileStartUUID
	lockBox.FileEncKey = newFileKey
	lockBox.FileMacKey = newFileMACKey
	lockBox.Revoked = false

	cipherLockBox, err := SymEncryption(lockBox, lockboxEncKey, lockboxMacKey, userdata.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(lockboxUUID, cipherLockBox)

	//iterate through lockboxes in recipientToLockboxUUIDMap and update their values to newfilekeys and uuid
	for username, usernamesLockBoxUUID := range recipientToLockboxUUIDMap {
		//username is the recipient we want to keep access so update their lockboxes
		usernamesLockBoxEncKey := recipientToLockboxEncKeyMap[username]
		usernamesLockBoxMacKey := recipientToLockboxMacKeyMap[username]

		usernameLBCipher, ok := userlib.DatastoreGet(usernamesLockBoxUUID)
		if !ok {
			return errors.New("recipient's lockbox does not exist")
		}

		var usernameLB LockBox
		err := SymDecryption(usernameLBCipher, usernamesLockBoxEncKey, usernamesLockBoxMacKey, &usernameLB, userdata.Username)
		if err != nil {
			return err
		}
		if username != recipientUsername { //if username is not a user we want to revoke, change their LockBox values
			usernameLB.FileUUID = newFileStartUUID
			usernameLB.FileEncKey = newFileKey
			usernameLB.FileMacKey = newFileMACKey
			usernameLB.Revoked = false
		} else { //else just change Revoked value to true
			usernameLB.Revoked = true

		}

		usernameCipherLockBox, err := SymEncryption(usernameLB, usernamesLockBoxEncKey, usernamesLockBoxMacKey, userdata.Username)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(usernamesLockBoxUUID, usernameCipherLockBox)
	}

	//re encrypt and datastoreSet map
	encryptedMap, err := SymEncryption(mapCopy, userdata.EncKey, userdata.MacKey, userdata.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(mapUUID, encryptedMap)

	//re encrypt and datastoreSet fileStart at new UUID
	encryptedFileStart, err := SymEncryption(fileStartCopy, newFileKey, newFileMACKey, userdata.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newFileStartUUID, encryptedFileStart)
	return nil
}

// Helper Functions
func MakeUserKeys(username string, password string) (encKey []byte, macKey []byte, err error) {
	rootKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	user_encKey, err := userlib.HashKDF(rootKey, []byte("encryption"))
	if err != nil {
		return nil, nil, err
	}
	user_macKey, err := userlib.HashKDF(rootKey, []byte("mac"))
	
	if err != nil {
		return nil, nil, err
	}

	return user_encKey[:16], user_macKey[:16], nil
}

func SymEncryption(v any, encKey []byte, macKey []byte, name string) (ciphertext []byte, err error) {

	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	byteArr, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	cipher := userlib.SymEnc(encKey[:16], iv, byteArr)

	tag, err := userlib.HMACEval(macKey[:16], cipher)
	
	//fmt.Print("tag from encryption for " + name)
	if err != nil {
		return nil, err
	}
	
	ciphertextMac := append(cipher, tag...)
	return ciphertextMac, nil
}

func SymDecryption(ciphertextMac []byte, encKey []byte, macKey []byte, v any, name string) (err error) {
	
	ciphertext := ciphertextMac[:(len(ciphertextMac) - userlib.HashSizeBytes)] //extract ciphertext from combined HMAC

	tag := ciphertextMac[(len(ciphertextMac) - userlib.HashSizeBytes):]
	//fmt.Print("tag from decryption for" + name)
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
