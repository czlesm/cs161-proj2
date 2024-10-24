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
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
    var bobLaptop *client.User
    var ddd *client.User
    var eee *client.User
    var fff *client.User
    var ggg *client.User

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

    Describe("Tests", func() {
        Specify("Test: User", func() {
            userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
            
            alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			aliceLaptop, err = client.GetUser("alice", "123")
			Expect(err).ToNot(BeNil())

            aliceLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
        })

        Specify("Test: Store/Load/Append", func() {
            alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

            aliceLaptop, err = client.GetUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            
            _, err = aliceLaptop.LoadFile("abc")
            Expect(err).ToNot(BeNil())
            err = aliceLaptop.AppendToFile("abc", []byte("123"))
            Expect(err).ToNot(BeNil())
            aliceLaptop.StoreFile("abc", []byte("123"))
            data, err := aliceLaptop.LoadFile("abc")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte("123")))
            aliceLaptop.AppendToFile("abc", []byte("456"))
            data, err = aliceLaptop.LoadFile("abc")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte("123456")))

            bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

            bobLaptop, err = client.GetUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            data, err = bobLaptop.LoadFile("abc")
            Expect(err).ToNot(BeNil())
        })

        Specify("Test: Store/Load/Append + interrupt", func() {
            alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

            aliceLaptop, err = client.GetUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            
            x := userlib.DatastoreGetMap()
            // print x. keys
            _, err = aliceLaptop.LoadFile("def")
            Expect(err).ToNot(BeNil())
            err = aliceLaptop.AppendToFile("def", []byte("123"))
            Expect(err).ToNot(BeNil())
            aliceLaptop.StoreFile("def", []byte("123"))
            data, err := aliceLaptop.LoadFile("def")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte("123")))
            aliceLaptop.AppendToFile("def", []byte("456"))
            data, err = aliceLaptop.LoadFile("def")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte("123456")))
            y := userlib.DatastoreGetMap()
            for k := range y {
                v := y[k]
                if _, ok := x[k]; !ok {
                    v = append([]byte{1}, v...)
                    userlib.DatastoreSet(k, v)
                }
            }
            data, err = aliceLaptop.LoadFile("abc")
            Expect(err).ToNot(BeNil())
        })
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

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

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

            ddd, err = client.InitUser("ddd", defaultPassword)
			Expect(err).To(BeNil())

            eee, err = client.InitUser("eee", defaultPassword)
			Expect(err).To(BeNil())            

            fff, err = client.InitUser("fff", defaultPassword)
			Expect(err).To(BeNil())            

            ggg, err = client.InitUser("ggg", defaultPassword)
			Expect(err).To(BeNil())            

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

            
            invite, err = alice.CreateInvitation(aliceFile, "ddd")
            Expect(err).To(BeNil())
            err = ddd.AcceptInvitation("alice", invite, "ddd-file")
            Expect(err).To(BeNil())
            invite, err = ddd.CreateInvitation("ddd-file", "eee")
            Expect(err).To(BeNil())
            err = eee.AcceptInvitation("ddd", invite, "eee-file")
            Expect(err).To(BeNil())
            invite, err = eee.CreateInvitation("eee-file", "fff")
            Expect(err).To(BeNil())
            err = fff.AcceptInvitation("eee", invite, "fff-file")
            Expect(err).To(BeNil())
            invite, err = alice.CreateInvitation("not", "ggg")
            Expect(err).ToNot(BeNil())
            invite, err = alice.CreateInvitation(aliceFile, "ggg")
            Expect(err).To(BeNil())
            err = ggg.AcceptInvitation("alice", invite, "ggg-file")
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

            // ddd eee fff ggg can read to file
            data, err = ddd.LoadFile("ddd-file")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne)))
            data, err = eee.LoadFile("eee-file")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne)))
            data, err = fff.LoadFile("fff-file")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne)))
            data, err = ggg.LoadFile("ggg-file")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne)))

            err = fff.AppendToFile("fff-file", []byte(contentTwo))
            Expect(err).To(BeNil())
            data, err = fff.LoadFile("fff-file")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne + contentTwo)))

            data, err = ggg.LoadFile("ggg-file")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne + contentTwo)))

            data, err = alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne + contentTwo)))
            
		})

        

	})
})
