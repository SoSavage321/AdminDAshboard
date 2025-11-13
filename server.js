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

    res.json({ 
      message: "Login successful", 
      idToken: data.idToken, 
      refreshToken: data.refreshToken,
      expiresIn: data.expiresIn,
      email: data.email, 
      uid: data.localId 
    });

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
    // Fetch students/learners from Firestore
    const usersSnap = await admin.firestore().collection("users").get();
    const users = usersSnap.docs.map(doc => {
      const data = doc.data() || {};
      const name = data.fullName || data.displayName || data.name || data.email || null;
      return { id: doc.id, role: 'learner', name, ...data };
    });

    // Fetch teachers from Firestore and tag them with role 'teacher'
    const teachersSnap = await admin.firestore().collection("teachers").get();
    const teachers = teachersSnap.docs.map(doc => {
      const data = doc.data() || {};
      const name = data.fullName || data.displayName || data.name || data.email || null;
      return { id: doc.id, role: 'teacher', name, ...data };
    });

    // Combine lists - teachers and learners together, but first dedupe
    // by a canonical key so that documents that reference the same auth UID
    // (for example a teacher doc with a `uid` field and a user doc whose
    // id equals that same uid) are collapsed into a single logical user.
    const raw = [...users, ...teachers];
    const byKey = new Map();
    const makeKey = (u) => String(u.uid || u.userId || u.authUid || u.id || '');

    raw.forEach(u => {
      const key = makeKey(u);
      if (!byKey.has(key)) {
        // shallow clone to avoid mutating original
        const clone = Object.assign({}, u);
        clone.sourceIds = [u.id];
        byKey.set(key, clone);
        return;
      }

      // merge into existing entry
      const existing = byKey.get(key);
      // prefer teacher role if any entry is teacher
      existing.role = (existing.role === 'teacher' || u.role === 'teacher') ? 'teacher' : existing.role || u.role;
      // prefer a non-null name
      existing.name = existing.name || u.name;
      existing.email = existing.email || u.email;
      // keep an array of underlying Firestore ids for debugging/reference
      existing.sourceIds = Array.from(new Set([...(existing.sourceIds || []), u.id]));
      // keep the id that best matches the canonical key if possible
      if (String(existing.id) !== key && String(u.id) === key) existing.id = u.id;
      byKey.set(key, existing);
    });

    const combined = Array.from(byKey.values());

    // By default return only Firestore-backed users (so deleted Firestore docs disappear).
    // If the client explicitly requests auth accounts be merged, pass ?includeAuth=true
    const includeAuth = String(req.query.includeAuth || '').toLowerCase() === 'true';
    if (!includeAuth) {
      return res.json({ users: combined, counts: { firestore: combined.length, authOnly: 0, total: combined.length } });
    }

    // If includeAuth=true, merge Firebase Auth accounts (backwards-compatible behavior)
    const existingIds = new Set(combined.map(u => String(u.id)));
    const existingEmails = new Set(combined.map(u => (u.email || '').toLowerCase()));
    const existingAuthUids = new Set();
    combined.forEach(u => {
      const maybe = (u.uid || u.userId || u.authUid || null);
      if (maybe) existingAuthUids.add(String(maybe));
    });

    // Helper to detect if an auth UID is already represented by a Firestore doc id
    // Some projects use composite doc ids like "teacher_<uid>" or similar. We
    // should treat those as duplicates of the auth UID to avoid counting twice.
    const uidAppearsInExistingId = (uid) => {
      if (!uid) return false;
      uid = String(uid);
      for (const existing of existingIds) {
        if (!existing) continue;
        const existingStr = String(existing);
        if (existingStr === uid) return true;                // exact match
        if (existingStr.includes(uid)) return true;           // e.g. teacher_<uid>
        if (uid.includes(existingStr)) return true;           // rare but defensive
      }
      return false;
    };

    let nextPageToken = undefined;
    const authOnly = [];
    do {
      const listResult = await admin.auth().listUsers(1000, nextPageToken);
      nextPageToken = listResult.pageToken;

      listResult.users.forEach(u => {
        const uid = String(u.uid);
        const email = (u.email || '').toLowerCase();
        const displayName = u.displayName || u.email || null;

        // Consider duplicate if:
        // - a Firestore doc id exactly matches the auth uid
        // - a Firestore doc id contains the auth uid (e.g. "teacher_<uid>")
        // - the email already exists in Firestore
        // - an existing doc already has a stored uid/authUid field matching this uid
        const alreadyById = existingIds.has(uid) || uidAppearsInExistingId(uid);
        const alreadyByEmail = email && existingEmails.has(email);
        const alreadyByAuthUid = existingAuthUids.has(uid);

        if (!alreadyById && !alreadyByEmail && !alreadyByAuthUid) {
          authOnly.push({ id: uid, role: 'learner', name: displayName, email: u.email, authOnly: true });
          existingIds.add(uid);
          if (email) existingEmails.add(email);
        }
      });
    } while (nextPageToken);

    const final = [...combined, ...authOnly];
    res.json({ users: final, counts: { firestore: combined.length, authOnly: authOnly.length, total: final.length } });
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

// ---------------- Fetch Learner Score ----------------
// GET /api/users/:id/score -> { id, name, score }
app.get('/api/users/:id/score', async (req, res) => {
  const userId = req.params.id;

  try {
    const docRef = admin.firestore().collection('users').doc(userId);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const data = doc.data() || {};

    // Pick the name
    const name = data.fullName || data.displayName || data.name || data.email || null;

    // Fetch totalScore only
    const totalScore = Number(data.totalScore) || 0;

    res.json({ id: doc.id, name, totalScore });
  } catch (err) {
    console.error('Error fetching user totalScore:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Progress Aggregation ----------------
// GET /api/progress -> { progress: [ { id, name, grade, school, avgScore, quizzesCompleted, lastActive } ] }
app.get('/api/progress', async (req, res) => {
  try {
    // fetch all users (learners)
    const usersSnap = await admin.firestore().collection('users').get();
    const users = usersSnap.docs.map(doc => ({ id: doc.id, ...(doc.data() || {}) }));

    // fetch quiz results
    const qrSnap = await admin.firestore().collection('quiz_results').get();
    const quizResults = qrSnap.docs.map(doc => ({ id: doc.id, ...(doc.data() || {}) }));

    // map quiz results by userId (tolerant to field naming)
    const byUser = new Map();
    quizResults.forEach(q => {
      const userId = q.userId || q.user_id || q.uid || q.user || null;
      if (!userId) return;
      const key = String(userId);
      if (!byUser.has(key)) byUser.set(key, []);
      byUser.get(key).push(q);
    });

    const percentKeys = ['percentage','percent','scorePercent','percentScore','percentageScore','percentile','percent_score','score_percentage'];
    const completedKeys = ['completedAt','completed_at','completed','completedOn','finishedAt','finished_at'];

    const progress = users.map(u => {
      const entries = byUser.get(String(u.id)) || [];

      let sum = 0, count = 0;
      entries.forEach(e => {
        let v = null;
        for (const k of percentKeys) { if (e[k] != null) { v = Number(e[k]); break; } }
        if (v == null && e.result && typeof e.result === 'object') {
          for (const k of percentKeys) { if (e.result[k] != null) { v = Number(e.result[k]); break; } }
        }
        if (v != null && !Number.isNaN(v)) { sum += v; count++; }
      });
      const avg = count > 0 ? (sum / count) : null;

      const quizzesCompleted = entries.reduce((acc, e) => {
        for (const k of completedKeys) {
          if (e[k]) return acc + 1;
        }
        if (e.result && typeof e.result === 'object') {
          for (const k of completedKeys) if (e.result[k]) return acc + 1;
        }
        return acc;
      }, 0);

      return {
        id: u.id,
        name: u.fullName || u.displayName || u.name || u.email || null,
        grade: u.grade || null,
        school: u.school || u.schoolName || null,
        avgScore: avg != null ? Number(avg) : null,
        quizzesCompleted,
        lastActive: u.lastActive || null
      };
    });

    res.json({ progress });
  } catch (err) {
    console.error('Error computing progress:', err);
    res.status(500).json({ error: err.message });
  }
});


  // ---------------- Delete User (Firestore + optional Auth) ----------------
  // Protected: accepts Authorization: Bearer <idToken> (preferred) and checks customClaim `admin: true`.
  // Fallback for local/dev: send header `x-admin-key: <ADMIN_KEY>` which must match process.env.ADMIN_KEY.
  // Query param: ?deleteAuth=true to also delete the Firebase Auth user (if the Firestore doc contains a uid/userId).
  app.delete('/api/users/:id', async (req, res) => {
    const id = req.params.id;
    const authHeader = (req.headers.authorization || '').toString();
    const adminKeyHeader = (req.headers['x-admin-key'] || '').toString();

    // Helper to reject unauthorized
    const unauthorized = (msg = 'Unauthorized') => res.status(401).json({ error: msg });

    try {
      let isAdmin = false;
      console.log(`[DELETE /api/users/${id}] Auth header present:`, !!authHeader);
      console.log('[DELETE] Admin key header present:', !!adminKeyHeader);

      // Try verify idToken first
      if (authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        console.log('[DELETE] Token starts with Bearer, attempting verification...');
        try {
          const decoded = await admin.auth().verifyIdToken(token);
          console.log('[DELETE] Token verified. Decoded:', JSON.stringify(decoded, null, 2));
          console.log('[DELETE] Admin claim value:', decoded?.admin);
          if (decoded && decoded.admin === true) {
            isAdmin = true;
            console.log('[DELETE] ✓ Admin claim verified: true');
          } else {
            // Fallback: check if the user has admin custom claim in the auth system
            console.log('[DELETE] Token verified but admin claim is missing or false. Checking user record...');
            try {
              const user = await admin.auth().getUser(decoded.uid);
              console.log('[DELETE] User record fetched:', { uid: user.uid, customClaims: user.customClaims });
              if (user.customClaims?.admin === true) {
                isAdmin = true;
                console.log('[DELETE] ✓ Admin claim found in user record');
              } else {
                console.log('[DELETE] User record does not have admin claim');
              }
            } catch (e) {
              console.warn('[DELETE] Failed to fetch user record for admin check', e && e.message);
            }
          }
        } catch (e) {
          console.warn('[DELETE] Invalid idToken for delete request:', e && e.message);
        }
      } else {
        console.log('[DELETE] No Bearer token in Authorization header');
      }

      // If not admin via token, allow ADMIN_KEY fallback for dev/testing
      if (!isAdmin && adminKeyHeader && process.env.ADMIN_KEY && adminKeyHeader === process.env.ADMIN_KEY) {
        isAdmin = true;
        console.log('[DELETE] ✓ Admin via ADMIN_KEY fallback');
      }

      console.log('[DELETE] Final isAdmin:', isAdmin);
      if (!isAdmin) return unauthorized('Admin credentials required');

      // Delete Firestore documents that reference this id. Try common collections: users, teachers
      const deleted = [];
      const collectionsToCheck = ['users', 'teachers'];
      for (const col of collectionsToCheck) {
        const ref = admin.firestore().collection(col).doc(id);
        const snap = await ref.get();
        if (snap.exists) {
          await ref.delete();
          deleted.push({ collection: col, id });
        } else {
          // also try to find documents where a `uid` or `userId` field equals the id
          const q = await admin.firestore().collection(col).where('uid', '==', id).get();
          if (!q.empty) {
            for (const d of q.docs) {
              await admin.firestore().collection(col).doc(d.id).delete();
              deleted.push({ collection: col, id: d.id });
            }
          }
          const q2 = await admin.firestore().collection(col).where('userId', '==', id).get();
          if (!q2.empty) {
            for (const d of q2.docs) {
              await admin.firestore().collection(col).doc(d.id).delete();
              deleted.push({ collection: col, id: d.id });
            }
          }
        }
      }

      // Optionally delete the Firebase Auth user if requested
      const deleteAuth = String(req.query.deleteAuth || '').toLowerCase() === 'true';
      let authDeleted = false;
      if (deleteAuth) {
        // Try to resolve a uid from the deleted documents or treat the id as a uid
        let uidToDelete = id;
        // look for any recently deleted doc that had a uid field (best-effort)
        try {
          // attempt to get user doc in users collection (even if deleted above this is safe)
          const udoc = await admin.firestore().collection('users').doc(id).get();
          if (udoc.exists) {
            const d = udoc.data() || {};
            uidToDelete = d.uid || d.userId || uidToDelete;
          }
        } catch (e) {
          // ignore
        }

        try {
          await admin.auth().deleteUser(uidToDelete);
          authDeleted = true;
        } catch (e) {
          // If deletion fails, log and continue (for example uid may not exist)
          console.warn('Failed to delete auth user', uidToDelete, e && e.message);
        }
      }

      res.json({ message: 'Delete operation completed', deleted, authDeleted });
    } catch (err) {
      console.error('Error deleting user:', err);
      res.status(500).json({ error: err.message });
    }
  });




// ---------------- Start Server ----------------
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

