require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const admin = require("./firebaseAdmin");

const app = express();
app.use(cors());
app.use(bodyParser.json());


// ---------------- Admin Registration ----------------
app.post("/api/register", async (req, res) => {
  const { fullName, email, password, adminKey } = req.body;

  try {
    if (adminKey !== process.env.ADMIN_KEY) {
      return res.status(403).json({ error: "Invalid Administrator Key" });
    }

    const user = await admin.auth().createUser({
      email,
      password,
      displayName: fullName,
    });

    await admin.auth().setCustomUserClaims(user.uid, { admin: true });

    res.status(201).json({
      message: "Admin registered successfully",
      uid: user.uid,
      email: user.email,
      fullName: user.displayName,
    });

  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


// ---------------- Admin Login ----------------
require("node-fetch"); // Node 18+ has fetch built-in

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      }
    );

    const data = await response.json();

    if (data.error) return res.status(400).json({ error: data.error.message });

    const user = await admin.auth().getUser(data.localId);
    if (!user.customClaims?.admin) {
      return res.status(403).json({ error: "Not an admin account" });
    }

    res.json({ message: "Login successful", idToken: data.idToken, email: data.email });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


const SibApiV3Sdk = require("sib-api-v3-sdk");



// ---------------- Configure Brevo ----------------
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const tranEmailApi = new SibApiV3Sdk.TransactionalEmailsApi();
defaultClient.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;

// ---------------- Create Teacher ----------------
app.post("/api/teachers", async (req, res) => {
  const { email, fullName } = req.body;

  if (!email || !fullName) {
    return res.status(400).json({ error: "Email and fullName are required" });
  }

  try {
    // 1. Save teacher in Firestore
    const teacherRef = await admin.firestore().collection("teachers").add({
      fullName,
      email,
      status: "invited",
      createdAt: new Date().toISOString(),
    });

    // 2. Generate invite link
    const inviteLink = `${process.env.TEACHER_REGISTRATION_URL}?id=${teacherRef.id}&email=${encodeURIComponent(email)}`;

    // 3. Build email
    const sendSmtpEmail = {
      sender: { email: process.env.SENDER_EMAIL, name: process.env.SENDER_NAME },
      to: [{ email, name: fullName }],
      subject: "You're invited to FunPlusMath as a Teacher",
      htmlContent: `
        <p>Hello ${fullName},</p>
        <p>You’ve been invited to join <b>FunPlusMath</b> as a teacher.</p>
        <p>Click the link below to complete your registration:</p>
        <p><a href="${inviteLink}">Complete Registration</a></p>
        <p>If you didn’t expect this email, please ignore it.</p>
      `,
    };

    // 4. Send via Brevo
    const response = await tranEmailApi.sendTransacEmail(sendSmtpEmail);

    res.status(201).json({
      message: "Teacher invited successfully, email sent via Brevo",
      teacherId: teacherRef.id,
      brevoResponse: response,
    });

  } catch (err) {
    console.error("❌ Brevo error:", err);
    if (err.response) console.error("Brevo response:", err.response.body);
    res.status(500).json({ error: err.response ? err.response.body : err.message });
  }
});
// ---------------- Fetch Users ----------------
// ---------------- Fetch Users (improved formatting) ----------------
app.get("/api/users", async (req, res) => {
  try {
    const usersSnap = await admin.firestore().collection("users").get();
    const users = usersSnap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json({ users });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: err.message });
  }
});
// SSE: Server-Sent Events for realtime presence
app.get('/api/users/stream', (req, res) => {
  res.set({
    'Cache-Control': 'no-cache',
    'Content-Type': 'text/event-stream',
    Connection: 'keep-alive'
  });
  res.flushHeaders();

  // helper to send event
  const sendEvent = (name, payload) => {
    res.write(`event: ${name}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  };

  // Listen to both collections (teachers + users)
  const usersUnsub = admin.firestore().collection('users')
    .onSnapshot(snapshot => {
      const changes = snapshot.docChanges().map(ch => ({
        type: ch.type,
        id: ch.doc.id,
        data: ch.doc.data()
      }));
      sendEvent('users-changed', changes);
    }, err => {
      console.error('users stream error', err);
      sendEvent('error', { message: 'users stream error' });
    });

  const teachersUnsub = admin.firestore().collection('teachers')
    .onSnapshot(snapshot => {
      const changes = snapshot.docChanges().map(ch => ({
        type: ch.type,
        id: ch.doc.id,
        data: ch.doc.data()
      }));
      sendEvent('teachers-changed', changes);
    }, err => {
      console.error('teachers stream error', err);
      sendEvent('error', { message: 'teachers stream error' });
    });

  // Clean up on client disconnect
  req.on('close', () => {
    usersUnsub();
    teachersUnsub();
    res.end();
  });
});


// ---------------- Fetch Bug Reports ----------------
app.get('/api/bug-reports', async (req, res) => {
  try {
    const snap = await admin.firestore().collection('bug_reports').get();
    const formatTimestamp = (ts) => {
      if (!ts) return null;
      if (typeof ts.toDate === 'function') return ts.toDate().toISOString();
      return new Date(ts).toISOString();
    };

    const reports = snap.docs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        timestamp: formatTimestamp(data.timestamp)
      };
    });

    res.json({ bugReports: reports });
  } catch (err) {
    console.error('Error fetching bug reports:', err);
    res.status(500).json({ error: err.message });
  }
});



// ---------------- Start Server ----------------
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

