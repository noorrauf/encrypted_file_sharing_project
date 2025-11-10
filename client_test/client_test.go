package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "Zohran Mamdani for the win!"
const contentFive = "Ummah Gala"
const contentSix = "we're cooked"
const contentSeven = "I'm tired of this Grandpa"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var rayana *client.User
	var noor *client.User
	var dima *client.User
	var yusrah *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	rayanaFile := "rayanaFile.txt"
	noorFile := "noorFile.txt"
	dimaFile := "dimaFile.txt"
	yusrahFile := "yusrahFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("stored file with " + contentOne)

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("appended file with " + contentTwo)

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("appended file with " + contentOne + contentTwo + contentThree)

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob created invitation for Charles")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("everything until alice revoke bob works")

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
		// our tests:
	})
	Describe("GetUser Tests", func() {
		Specify("Datastore get user fail", func() {
			userlib.DebugMsg("Get a user from the Datastore and check if user exists")
			alice, err = client.InitUser("alice", defaultPassword)
			_, err = client.GetUser("alice", "Wrong_Passoword")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Tamper with datastore, so GetUser should fail ")
			//for every key , change last bit of value
			for k := range userlib.DatastoreGetMap() {
				v := userlib.DatastoreGetMap()[k]
				v[len(v)-1] ^= 0xFF
				userlib.DatastoreGetMap()[k] = v
			}
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})
		Specify("Duplicate Username", func() {
			userlib.DebugMsg("Duplication username should fail")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.InitUser("alice", "password3")
			Expect(err).ToNot(BeNil())
		})
	})

	//Integrity Test for File
	Describe("Store/Loading File Test", func() {
		Specify("Tampering with a stored file and loading it get user fail", func() {
			userlib.DebugMsg("tamper the file stored")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			//for every key , change last bit of value
			for k := range userlib.DatastoreGetMap() {
				v := userlib.DatastoreGetMap()[k]
				v[0] ^= 0xFF
				userlib.DatastoreGetMap()[k] = v
			}
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})
		Specify("Filename stored twice", func() {
			userlib.DebugMsg("Alice stores file x, and stores x again, then x should overwrite original x, not add to datstore")
			alice, err = client.InitUser("alice", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))

			//lengthOfDatastore := len(userlib.DatastoreGetMap())

			alice.StoreFile(aliceFile, []byte(contentTwo))
			//newLengthOfDatastore := len(userlib.DatastoreGetMap())
			//Expect(newLengthOfDatastore).To(Equal(lengthOfDatastore))
			userlib.DebugMsg("storeFile success")
			data, err := alice.LoadFile(aliceFile)
			Expect(data).To(Equal([]byte(contentTwo)))
			Expect(err).To(BeNil())
		})
	})

	Describe("Invitation Tests", func() {
		Specify("Invitation Integrity", func() {
			userlib.DebugMsg("Alice create invitation, it gets tampered, Bob should not accept")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte("come to my party"))
			invitationUUID, err := alice.CreateInvitation(aliceFile, bob.Username)
			Expect(err).To(BeNil())

			for k := range userlib.DatastoreGetMap() {
				v := userlib.DatastoreGetMap()[k]
				v[len(v)-1] ^= 0xFF
				userlib.DatastoreGetMap()[k] = v
			}

			err = bob.AcceptInvitation(alice.Username, invitationUUID, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Invitation from Bob Success", func() {
			userlib.DebugMsg("Alice shares with Bob, Bob Shares with Charles, revoke Bob, Bob and Charles can't loadFile")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))
			aliceFile_uuid, _ := alice.CreateInvitation(aliceFile, bob.Username)

			bob.AcceptInvitation(alice.Username, aliceFile_uuid, aliceFile)
			bobFromAlice_uuid, _ := bob.CreateInvitation(aliceFile, charles.Username)

			charles.AcceptInvitation(bob.Username, bobFromAlice_uuid, aliceFile)
			userlib.DebugMsg("accepted invitation")
			alice.RevokeAccess(aliceFile, bob.Username)

			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("HMAC Test", func() {
		Specify("Create and Verify HMAC", func() {
			userlib.DebugMsg("Alice signs in then logs in with same password, HMAC should be same")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			rootKey := userlib.Argon2Key([]byte(defaultPassword), []byte("0"), 16)
			firstHMAC, _ := userlib.HMACEval(rootKey, []byte(defaultPassword))
			_, err = client.GetUser(alice.Username, defaultPassword)
			secondHMAC, _ := userlib.HMACEval(rootKey, []byte("defaultPassword"))
			Expect(userlib.HMACEqual(firstHMAC, secondHMAC)).To(BeFalse())

		})
	})
	// 11/10 testing
	Describe("User Initialization and Authentication", func() {

		Specify("Rejects duplicate usernames and treats case differences separately", func() {
			userlib.DebugMsg("Creating initial user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to re-register with the same name.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(bob).To(BeNil())
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Trying a similar username with different capitalization.")
			bob, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Fails to get user when username is slightly incorrect", func() {
			userlib.DebugMsg("Registering 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to log in with a misspelled name.")
			bob, err = client.GetUser("alic", defaultPassword)
			Expect(bob).To(BeNil())
			Expect(err).ToNot(BeNil())
		})

		Specify("Detects incorrect passwords for an existing account", func() {
			userlib.DebugMsg("Creating account for alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Logging in with the wrong password.")
			alice, err = client.GetUser("alice", "badpassword")
			Expect(alice).To(BeNil())
			Expect(err).ToNot(BeNil())
		})

		Specify("Identifies datastore tampering with user data", func() {
			userlib.DebugMsg("Setting up user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with stored user information.")
			dataStore := userlib.DatastoreGetMap()
			for key, _ := range dataStore {
				dataStore[key] = []byte("tamper")
			}

			userlib.DebugMsg("Attempting to retrieve corrupted account.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(alice).To(BeNil())
			Expect(err).ToNot(BeNil())
		})

		Specify("Allows one user to log in from multiple devices", func() {
			userlib.DebugMsg("Creating primary account for Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Opening two new sessions for the same user.")
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Saving a file on one device.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading the same file on another device.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Appending data from phone and verifying from laptop.")
			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})
	})

	Describe("Core File Functionality", func() {

		Specify("Overwrites existing file contents when StoreFile is reused", func() {
			alice, _ = client.InitUser("alice", defaultPassword)

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			result, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(result).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Overwriting with new file data.")
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			result, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(result).To(Equal([]byte(contentTwo)))
		})

		Specify("Each user maintains independent namespaces for files", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)

			Expect(alice.StoreFile(aliceFile, []byte(contentOne))).To(BeNil())
			Expect(bob.StoreFile(aliceFile, []byte(contentTwo))).To(BeNil())
		})

		Specify("AppendToFile should consume constant bandwidth", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			Expect(alice.StoreFile(aliceFile, []byte(contentOne))).To(BeNil())

			before := userlib.DatastoreGetBandwidth()
			Expect(alice.AppendToFile(aliceFile, []byte(contentTwo))).To(BeNil())
			after := userlib.DatastoreGetBandwidth()

			Expect(after - before).To(BeNumerically("<", 3000))
		})

		/*Specify("Detects modification of file data in the datastore", func() {
			alice, _ = client.InitUser("alice", defaultPassword)

			oldMap := userlib.DatastoreGetMap()
			refCopy := make(map[uuid.UUID][]byte)
			for k, v := range oldMap {
				refCopy[k] = v
			}

			alice.StoreFile(aliceFile, []byte(contentOne))

			newMap := userlib.DatastoreGetMap()
			for k := range newMap {
				if _, found := refCopy[k]; !found {
					userlib.DatastoreSet(k, []byte("lalalala"))
				}
			}

			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())
		})*/

		Specify("Handles storing and reading empty or whitespace-only content", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			content := "      "
			Expect(alice.StoreFile(aliceFile, []byte(content))).To(BeNil())
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(content)))
		})

		Specify("Returns an error if loading a non-existent file", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile("unknown.txt")
			Expect(data).To(BeNil())
			Expect(err).ToNot(BeNil())
		})

		Specify("Prevents appending to an undefined file", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(alice.AppendToFile(aliceFile, []byte(contentTwo))).To(BeNil())

			err := alice.AppendToFile("ghost.txt", []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Sharing and Revocation Functionality", func() {

		Specify("Fails to create invitation if filename not found", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))
			_, err := alice.CreateInvitation("invalidfile", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Returns error when inviting an unknown recipient", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))
			_, err := alice.CreateInvitation(aliceFile, "ghost")
			Expect(err).ToNot(BeNil())
		})

		/*Specify("Prevents invitation creation after datastore tampering", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))
			dataStore := userlib.DatastoreGetMap()
			for key, _ := range dataStore {
				dataStore[key] = []byte("tamper")
			}
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})*/

		Specify("Allows shared users to propagate access to others", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)
			charles, _ = client.InitUser("charles", defaultPassword)

			alice.StoreFile(aliceFile, []byte(contentOne))
			inv, _ := alice.CreateInvitation(aliceFile, "bob")
			bob.AcceptInvitation("alice", inv, bobFile)

			_, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
		})

		/*Specify("Rejects invitation acceptance when filename already in use", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)

			alice.StoreFile(aliceFile, []byte(contentOne))
			bob.StoreFile(bobFile, []byte(contentTwo))

			inv, _ := alice.CreateInvitation(aliceFile, "bob")
			err := bob.AcceptInvitation("alice", inv, bobFile)
			Expect(err).ToNot(BeNil())
		})*/

		Specify("Detects corrupted invitations before acceptance", func() {
			alice, _ = client.InitUser("alice", defaultPassword)
			bob, _ = client.InitUser("bob", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))

			old := userlib.DatastoreGetMap()
			ref := make(map[uuid.UUID][]byte)
			for k, v := range old {
				ref[k] = v
			}

			inv, _ := alice.CreateInvitation(aliceFile, "bob")

			for k := range userlib.DatastoreGetMap() {
				if _, exists := ref[k]; !exists {
					userlib.DatastoreSet(k, []byte("corrupted"))
				}
			}

			err := bob.AcceptInvitation("alice", inv, bobFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Additional Tests", func() {

		Specify("file shared among multiple users who append to it", func() {
			userlib.DebugMsg("Initializing user Alice with username alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user rayana.")
			rayana, err = client.InitUser("rayana", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user noor.")
			noor, err = client.InitUser("noor", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user dima.")
			dima, err = client.InitUser("dima", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user yusrah.")
			yusrah, err = client.InitUser("yusrah", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s with name %s", contentOne, aliceFile)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file with name %s with recipient rayana", aliceFile)
			invitation, err := alice.CreateInvitation(aliceFile, "rayana")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Rayana accepting invitation")
			err = rayana.AcceptInvitation("alice", invitation, rayanaFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file with name %s with recipient noor", aliceFile)
			invitation, err = alice.CreateInvitation(aliceFile, "noor")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Noor accepting invitation")
			err = noor.AcceptInvitation("alice", invitation, noorFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file with name %s with recipient dima", aliceFile)
			invitation, err = alice.CreateInvitation(aliceFile, "dima")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Dima accepting invitation")
			err = dima.AcceptInvitation("alice", invitation, dimaFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file with name %s with recipient yusrah", aliceFile)
			invitation, err = alice.CreateInvitation(aliceFile, "yusrah")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Yusrah accepting invitation")
			err = yusrah.AcceptInvitation("alice", invitation, yusrahFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Rayana appending to file, content: %s", contentFive)
			err = rayana.AppendToFile(rayanaFile, []byte(contentFive))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Noor appending to file, content: %s", contentFour)
			err = noor.AppendToFile(noorFile, []byte(contentFour))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Dima appending to file, content: %s", contentSix)
			err = dima.AppendToFile(dimaFile, []byte(contentSix))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Yusrah appending to file, content: %s", contentSeven)
			err = yusrah.AppendToFile(yusrahFile, []byte(contentSeven))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Noor appending to file, content: %s", "contentEight")
			err = noor.AppendToFile(noorFile, []byte("contentEight"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentFive + contentFour + contentSix + contentSeven + "contentEight")))
		})

		Specify("Revoke user; remaining/kept users can still access file", func() {
			userlib.DebugMsg("Initializing multiple users")
			rayana, err = client.InitUser("rayana", defaultPassword)
			Expect(err).To(BeNil())
			noor, err = client.InitUser("noor", defaultPassword)
			Expect(err).To(BeNil())
			dima, err = client.InitUser("dima", defaultPassword)
			Expect(err).To(BeNil())
			yusrah, err = client.InitUser("yusrah", defaultPassword)
			Expect(err).To(BeNil())

			err = rayana.StoreFile(rayanaFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file %s with recipient noor", rayanaFile)
			invitation, err := rayana.CreateInvitation(rayanaFile, "noor")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Noor accepting invitation")
			err = noor.AcceptInvitation("rayana", invitation, noorFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file %s with recipient dima", noorFile)
			invitation, err = noor.CreateInvitation(noorFile, "dima")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Dima accepting invitation")
			err = dima.AcceptInvitation("noor", invitation, dimaFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing file %s with recipient yusrah", rayanaFile)
			invitation, err = rayana.CreateInvitation(rayanaFile, "yusrah")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Yusrah accepting invitation")
			err = yusrah.AcceptInvitation("rayana", invitation, yusrahFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking access from noor")
			err = rayana.RevokeAccess(rayanaFile, "noor")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Noor load file -> error")
			_, err = noor.LoadFile(noorFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Dima load file -> error")
			_, err = dima.LoadFile(dimaFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Yusrah load file -> no error")
			_, err = yusrah.LoadFile(yusrahFile)
			Expect(err).To(BeNil())
		})

	})

})

/* call with client/name.___
InitUser
GetUser
StoreFile
LoadFile
AppendToFile
CreateInvitation
AcceptInvitation
RevokeAccess
*/

/*userlib
userlib.uuid
userlib.hmacEval(key, msg) --> byte array,error
userlib.hmacEqual(byte array, byte array) --> yes or no
*/
