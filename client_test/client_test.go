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
	var aisha *client.User
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
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
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

			/*userlib.DebugMsg("Checking that Alice can still load the file.")
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
			Expect(err).ToNot(BeNil())*/
		})

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
