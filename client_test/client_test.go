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

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
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

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

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
		})

		Specify("Test Get User and Wrong Password", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Running Get User on Alice")
			a, err := client.GetUser("alice", "fubar")
			Expect(err).To(BeNil())
			Expect(a).ToNot(BeNil())
			userlib.DebugMsg("Got alice")

			userlib.DebugMsg("Running Get User on Alice with wrong password")
			b, err := client.GetUser("alice", "alicePassword")
			Expect(err).ToNot(BeNil())
			Expect(b).To(BeNil())
			userlib.DebugMsg("Alice's password is incorrect")

		})

		Specify("Test File Storage", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("Thissa test file")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())
		})

		Specify("Test Appending and Modifying File", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("Thissa Test File")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())

			appendage := []byte(" Appended")
			err3 := alice.AppendToFile("file1", appendage)
			Expect(err3).To(BeNil())

			//Load the file again
			aliceFile, err4 := alice.LoadFile("file1")
			Expect(err4).To(BeNil())
			userlib.DebugMsg("Found Alice's Appended File: ", aliceFile)
		})

		Specify("Test Unshared User Trying to Modify a File of a Different Owner", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("This is Alice")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())

			bobAccess, err3 := bob.LoadFile("file1")
			Expect(err3).ToNot(BeNil())
			Expect(bobAccess).To(BeNil())
			userlib.DebugMsg("Bob Is Unable to Access Alice's Files")
		})

		//THIS ONE WORKS COPY LAYOUT FOR SHARING FROM LINES 376-382
		Specify("Test Sharing and Revokes", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("This is Alice")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())

			invite, errorrr1 := alice.CreateInvitation("file1", "charles")
			Expect(errorrr1).To(BeNil())
			errorr2 := charles.AcceptInvitation("alice", invite, "file1")
			Expect(errorr2).To(BeNil())
			aliceShare, err3 := alice.CreateInvitation("file1", "charles")
			Expect(aliceShare).ToNot(BeNil())
			Expect(err3).To(BeNil())

			userlib.DebugMsg("Bob should not be able to access Alice's File .. Testing Now")
			bobTrynaAccess, err4 := bob.LoadFile("file1")
			Expect(bobTrynaAccess).To(BeNil())
			Expect(err4).ToNot(BeNil())

			userlib.DebugMsg("Now Testing: Charles Reading Alice's Shared File")
			charlesTrynaAccess, err5 := charles.LoadFile("file1")
			Expect(charlesTrynaAccess).ToNot(BeNil())
			Expect(err5).To(BeNil())

			userlib.DebugMsg("Now Revoking Access to Charles From Alice")
			err6 := alice.RevokeAccess("file1", "charles")
			Expect(err6).To(BeNil())
			userlib.DebugMsg("Access Revoked to Charles")
			charlesRead, err7 := charles.LoadFile("file1")
			Expect(charlesRead).To(BeNil())
			Expect(err7).ToNot(BeNil())

		})

		Specify("Test Share Multiple Files with One User", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("This is Alice")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())

			file2 := []byte("This is Alice's Second File")
			err3 := alice.StoreFile("file2", file2)
			Expect(err3).To(BeNil())
			userlib.DebugMsg("Stored Second file for Alice")
			f2, err4 := alice.LoadFile("file2")
			Expect(err4).To(BeNil())
			Expect(f2).ToNot(BeNil())

			//Alice should then create invite and share both files with bob.
			//Bob should be able to acces both, but charles cannot.

		})

		Specify("Test Share and Revocation, Then Make Changes to File and Check that Changes are Reflected", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubara")
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", "fubarb")
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", "fubarc")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("This is Alice")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())

			aliceinvitesbob, errorrr3 := alice.CreateInvitation("file1", "bob")
			Expect(errorrr3).To(BeNil())
			errorr4 := bob.AcceptInvitation("alice", aliceinvitesbob, "file1")
			Expect(errorr4).To(BeNil())
			aliceSharetoBOB, err4 := alice.CreateInvitation("file1", "bob")
			Expect(aliceSharetoBOB).ToNot(BeNil())
			Expect(err4).To(BeNil())
			userlib.DebugMsg("Successfully shared to Bob")

			invite, errorrr1 := alice.CreateInvitation("file1", "charles")
			Expect(errorrr1).To(BeNil())
			errorr2 := charles.AcceptInvitation("alice", invite, "file1")
			Expect(errorr2).To(BeNil())
			aliceSharetoCHARLES, err3 := alice.CreateInvitation("file1", "charles")
			Expect(aliceSharetoCHARLES).ToNot(BeNil())
			Expect(err3).To(BeNil())
			userlib.DebugMsg("Successfully shared to Charles")

			bobreadsfile1, errorfirsttime := bob.LoadFile("file1")
			Expect(errorfirsttime).To(BeNil())
			Expect(bobreadsfile1).ToNot(BeNil())

			userlib.DebugMsg("Making Changes to Alice's File")
			file2 := []byte("Changes MADE Muahahaha")
			error5 := alice.StoreFile("file1", file2)
			Expect(error5).To(BeNil())
			userlib.DebugMsg("Appending Some More Garbage")
			file3 := []byte("Actual Garbage")
			error6 := alice.AppendToFile("file1", file3)
			Expect(error6).To(BeNil())
			userlib.DebugMsg("Alice's File Has Been Changed")

			userlib.DebugMsg("Taking Away Bob's Rights")
			error7 := alice.RevokeAccess("file1", "bob")
			Expect(error7).To(BeNil())

			bobreadsfile2, error9 := bob.LoadFile("file1")
			Expect(bobreadsfile2).To(BeNil())
			Expect(error9).ToNot(BeNil())

			// invitingbobagain, erron := alice.CreateInvitation("file1", "bob")
			// Expect(erron).To(BeNil())
			// Expect(invitingbobagain).ToNot(BeNil())
			// erron2 := bob.AcceptInvitation("alice", invitingbobagain, "file1")
			// Expect(erron2).ToNot(BeNil())
			// aliceShareToBob, err3 := alice.ShareFile("file1", "bob")
			// Expect(aliceShareToBob).ToNot(BeNil())
			// Expect(err3).To(BeNil())

			// bobreadsfile3, error12 := bob.LoadFile("file1")
			// Expect(bobreadsfile3).To(BeNil())
			// Expect(error12).To(BeNil())

			// Expect(bobreadsfile3).To(Equal([]byte(charlesreadsfile1)))
		})

		Specify("Test Non Unique File Names", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", "fuwar")
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", "funar")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("This is Alice")
			err1 := alice.StoreFile("file1", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("file1")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())

			userlib.DebugMsg("Storing files for Bob")
			filee := []byte("This is Bob")
			err3 := bob.StoreFile("file1", filee)
			Expect(err3).To(BeNil())
			userlib.DebugMsg("Stored file for Bob")
			g, err4 := bob.LoadFile("file1")
			Expect(err4).To(BeNil())
			Expect(g).ToNot(BeNil())

			userlib.DebugMsg("Storing files for Charles")
			fileee := []byte("This is Charles")
			err5 := charles.StoreFile("file1", fileee)
			Expect(err5).To(BeNil())
			userlib.DebugMsg("Stored file for Charles")
			h, err6 := charles.LoadFile("file1")
			Expect(err6).To(BeNil())
			Expect(h).ToNot(BeNil())

			Expect(f).ToNot(Equal([]byte(g)))
			Expect(g).ToNot(Equal([]byte(h)))
			Expect(h).ToNot(Equal([]byte(f)))
		})

		Specify("Test Empty Filename", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "fubar")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing files for Alice")
			file := []byte("This is Alice")
			err1 := alice.StoreFile("", file)
			Expect(err1).To(BeNil())
			userlib.DebugMsg("Stored file for Alice")
			f, err2 := alice.LoadFile("")
			Expect(err2).To(BeNil())
			Expect(f).ToNot(BeNil())
			userlib.DebugMsg("Alice was able to successfully load a file with an empty filename.")

			bobAccess, err3 := bob.LoadFile("")
			Expect(err3).ToNot(BeNil())
			Expect(bobAccess).To(BeNil())
			userlib.DebugMsg("Bob Is Unable to Access Alice's File")
		})
	})
})
