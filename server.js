
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const { Pool } = require("pg");

// LICENCRENDSZER
const {
  registerLicenseRoutes,
  initializeLicenseTables
} = require("./license-system");

const app = express();
app.set("trust proxy", 1);

const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(express.json({ limit: "2mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,X-Admin-Api-Key"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Supabase adatbázis-kapcsolat
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

// LICENCKULCS-KEZELŐ API-VÉGPONTOK REGISZTRÁLÁSA
registerLicenseRoutes(app, pool);

// ANDROID ALKALMAZÁS FRISSÍTÉSI BEÁLLÍTÁSAI
const APP_VERSION_CODE = Number(process.env.APP_VERSION_CODE || 2);
const APP_VERSION_NAME = process.env.APP_VERSION_NAME || "1.1";
const MIN_SUPPORTED_VERSION_CODE = Number(
  process.env.MIN_SUPPORTED_VERSION_CODE || 2
);
const APK_DOWNLOAD_URL = process.env.APK_DOWNLOAD_URL || "";

// Régi Multiplayer szobák
const rooms = new Map();

// Online Rivális szobák
const onlineRivalRooms = new Map();

function makeCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function getCode(map) {
  let code;

  do {
    code = makeCode();
  } while (map.has(code));

  return code;
}

// ONLINE RIVÁLIS – kérdések ellenőrzése
function validateOnlineRivalQuestions(questions) {
  if (
    !Array.isArray(questions) ||
    questions.length === 0 ||
    questions.length > 500
  ) {
    return false;
  }

  return questions.every(q =>
    q &&
    typeof q.question === "string" &&
    q.question.trim().length > 0 &&
    Array.isArray(q.answers) &&
    q.answers.length === 4 &&
    q.answers.every(a => typeof a === "string") &&
    Number.isInteger(q.correct) &&
    q.correct >= 0 &&
    q.correct <= 3
  );
}

// ONLINE RIVÁLIS – nyilvános játékosadatok
function getOnlineRivalPublicPlayers(room) {
  return room.players.map(player => ({
    name: player.name,
    cups: player.cups,
    submitted: player.submitted
  }));
}

// ONLINE RIVÁLIS – időzítők törlése
function clearOnlineRivalTimers(room) {
  if (!room) return;

  room.players.forEach(player => {
    if (player.timer) {
      clearTimeout(player.timer);
      player.timer = null;
    }
  });
}

// ONLINE RIVÁLIS – biztonságos kérdésküldés
function sendOnlineRivalQuestion(code, room) {
  const question = room.questions[room.questionIndex];

  if (!question) return;

  room.players.forEach((player, index) => {
    const activeEffects = { ...player.effects };

    // A következő kérdésre időzített Pohár-sózás aktiválása
    player.activeSteal = player.pendingSteal;
    player.pendingSteal = false;

    // A következő kérdésre időzített hatások felhasználása
    player.effects = {
      blind: false,
      timer: false,
      block5050: false
    };

    const safeQuestion = {
      question: question.question,
      answers: [...question.answers]
    };

    io.to(player.id).emit("online-rival:question", {
      index: room.questionIndex,
      total: room.questions.length,
      question: safeQuestion,
      cups: player.cups,
      opponent: room.players[1 - index]?.name || "Ellenfél",
      opponentCups: room.players[1 - index]?.cups ?? 10,
      effects: activeEffects
    });

    // 10 másodperces szerveroldali időkorlát
    if (activeEffects.timer) {
      const currentIndex = room.questionIndex;

      player.timer = setTimeout(() => {
        if (
          !onlineRivalRooms.has(code) ||
          !room.started ||
          room.resolved ||
          room.questionIndex !== currentIndex ||
          player.submitted
        ) {
          return;
        }

        const bets = [0, 0, 0, 0];

        for (let i = 0; i < player.cups; i++) {
          bets[crypto.randomInt(0, 4)]++;
        }

        player.bets = bets;
        player.submitted = true;
        player.timer = null;

        io.to(player.id).emit("online-rival:timeout", {
          message: "Lejárt az idő! Automatikus válasz."
        });

        io.to(code).emit("online-rival:submitted", {
          submittedCount: room.players.filter(p => p.submitted).length,
          totalPlayers: 2
        });

        resolveOnlineRivalRound(code, room);
      }, 10000);
    }
  });
}

// ONLINE RIVÁLIS – kör kiértékelése
function resolveOnlineRivalRound(code, room) {
  if (room.players.length !== 2) return;
  if (!room.players.every(player => player.submitted)) return;
  if (room.resolved) return;

  room.resolved = true;

  clearOnlineRivalTimers(room);

  const question = room.questions[room.questionIndex];
  const correctIndex = question.correct;

  const first = room.players[0];
  const second = room.players[1];

  const firstCorrect = first.bets[correctIndex];
  const secondCorrect = second.bets[correctIndex];

  first.cups = firstCorrect;
  second.cups = secondCorrect;

  // Pohár-sózás: ha a támadó legalább egy helyes poharat tett,
  // az ellenfél egy extra poharat veszít
  if (first.activeSteal && firstCorrect >= 1) {
    second.cups = Math.max(0, second.cups - 1);
  }

  if (second.activeSteal && secondCorrect >= 1) {
    first.cups = Math.max(0, first.cups - 1);
  }

  // Eredmények kiküldése csak mindkét beküldés után
  room.players.forEach((player, index) => {
    const opponent = room.players[1 - index];

    io.to(player.id).emit("online-rival:result", {
      correctIndex,
      correctGlasses: player.bets[correctIndex],
      remainingGlasses: player.cups,
      opponentCups: opponent.cups,
      opponentName: opponent.name,
      ownBets: player.bets,
      opponentBets: opponent.bets
    });
  });

  io.to(code).emit("online-rival:resolved", {
    players: getOnlineRivalPublicPlayers(room),
    questionIndex: room.questionIndex
  });
}

// Adatbázis és tábla automatikus létrehozása
async function initializeDatabase() {
  if (!pool) {
    throw new Error("A DATABASE_URL környezeti változó nincs beállítva!");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.quiz_shares (
      code TEXT PRIMARY KEY,
      questions JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // LICENCRENDSZER ADATBÁZISTÁBLÁINAK LÉTREHOZÁSA
  await initializeLicenseTables(pool);

  console.log("Supabase adatbázis csatlakoztatva!");
  console.log("quiz_shares tábla ellenőrizve!");
  console.log("Licencrendszer adatbázistáblái ellenőrizve!");
}

// FŐOLDAL
app.get("/", (req, res) => {
  res.send("Legyen Ön is Részeg – szerver működik! 🍻");
});

// ANDROID VERZIÓELLENŐRZÉS
app.get("/api/version", (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  res.json({
    success: true,
    versionCode: APP_VERSION_CODE,
    versionName: APP_VERSION_NAME,
    minSupportedVersionCode: MIN_SUPPORTED_VERSION_CODE,
    downloadUrl: APK_DOWNLOAD_URL
  });
});

// Kérdéssor megosztása – mentés Supabase-be
app.post("/api/share", async (req, res) => {
  const { questions } = req.body || {};

  if (!Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({
      error: "Érvénytelen kérdéssor."
    });
  }

  if (questions.length > 500) {
    return res.status(400).json({
      error: "Túl sok kérdés."
    });
  }

  try {
    for (let attempt = 0; attempt < 5; attempt++) {
      const code = makeCode();

      try {
        await pool.query(
          `INSERT INTO public.quiz_shares (code, questions)
           VALUES ($1, $2::jsonb)`,
          [code, JSON.stringify(questions)]
        );

        return res.json({
          success: true,
          code
        });
      } catch (error) {
        if (error.code !== "23505") {
          throw error;
        }
      }
    }

    return res.status(500).json({
      error: "Nem sikerült megosztási kódot létrehozni."
    });

  } catch (error) {
    console.error("Mentési hiba:", error);

    return res.status(500).json({
      error: "A kérdéssor mentése nem sikerült."
    });
  }
});

// Kérdéssor letöltése kód alapján
app.get("/api/share/:code", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT questions
       FROM public.quiz_shares
       WHERE code = $1`,
      [String(req.params.code)]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Ismeretlen kód."
      });
    }

    res.json({
      success: true,
      questions: result.rows[0].questions
    });

  } catch (error) {
    console.error("Betöltési hiba:", error);

    res.status(500).json({
      error: "A kérdéssor betöltése nem sikerült."
    });
  }
});

// Adatbázis állapotának ellenőrzése
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected"
    });

  } catch (error) {
    res.status(503).json({
      ok: false,
      database: "error"
    });
  }
});

// SOCKET.IO
io.on("connection", (socket) => {

  // =====================================================
  // RÉGI MULTIPLAYER – VÁLTOZATLAN
  // =====================================================

  // Szoba létrehozása
  socket.on("create-room", (data, callback) => {
    data = data || {};

    const questions = data.questions;

    if (!Array.isArray(questions) || questions.length === 0) {
      return callback?.({
        error: "Nincs kérdéssor."
      });
    }

    const code = getCode(rooms);

    const room = {
      host: socket.id,
      players: new Map(),
      questions,
      questionIndex: 0,
      started: false
    };

    room.players.set(socket.id, {
      name: String(data.name || "Játékos 1").slice(0, 20),
      submitted: false
    });

    rooms.set(code, room);
    socket.join(code);
    socket.data.roomCode = code;

    callback?.({
      success: true,
      code,
      players: [...room.players.values()]
    });
  });

  // Csatlakozás szobához
  socket.on("join-room", (data, callback) => {
    data = data || {};

    const code = String(data.code || "");
    const room = rooms.get(code);

    if (!room) {
      return callback?.({
        error: "Nem található ilyen szoba."
      });
    }

    if (room.started) {
      return callback?.({
        error: "A játék már elkezdődött."
      });
    }

    if (room.players.size >= 8) {
      return callback?.({
        error: "A szoba megtelt."
      });
    }

    room.players.set(socket.id, {
      name: String(data.name || "Játékos").slice(0, 20),
      submitted: false
    });

    socket.join(code);
    socket.data.roomCode = code;

    io.to(code).emit("player-joined", {
      players: [...room.players.values()]
    });

    callback?.({
      success: true,
      code
    });
  });

  // Játék indítása
  socket.on("start-game", (callback) => {
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room || room.host !== socket.id) {
      return callback?.({
        error: "Csak a szoba létrehozója indíthat."
      });
    }

    room.started = true;
    room.questionIndex = 0;

    sendQuestion(code, room);

    callback?.({
      success: true
    });
  });

  // Válasz elküldése
  socket.on("submit-answer", (data, callback) => {
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room || !room.started) {
      return callback?.({
        error: "Nincs aktív játék."
      });
    }

    const player = room.players.get(socket.id);

    if (!player || player.submitted) {
      return callback?.({
        error: "Már elküldted a válaszod."
      });
    }

    const bets = data && data.bets;

    if (
      !Array.isArray(bets) ||
      bets.length !== 4 ||
      !bets.every(n => Number.isInteger(n) && n >= 0) ||
      bets.reduce((a, b) => a + b, 0) !== 10
    ) {
      return callback?.({
        error: "Pontosan 10 poharat kell elhelyezned."
      });
    }

    const question = room.questions[room.questionIndex];
    const correctIndex = Number(question.correctIndex);

    if (
      !Number.isInteger(correctIndex) ||
      correctIndex < 0 ||
      correctIndex > 3
    ) {
      return callback?.({
        error: "Hibás kérdésadat."
      });
    }

    const correctGlasses = bets[correctIndex];

    player.submitted = true;

    socket.emit("answer-result", {
      correctGlasses,
      remainingGlasses: correctGlasses
    });

    const submittedCount = [...room.players.values()]
      .filter(p => p.submitted).length;

    io.to(code).emit("player-submitted", {
      submittedCount,
      totalPlayers: room.players.size
    });

    callback?.({
      success: true
    });
  });

  // Következő kérdés
  socket.on("next-question", (callback) => {
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room || room.host !== socket.id) {
      return callback?.({
        error: "Csak a házigazda léptethet."
      });
    }

    const allSubmitted = [...room.players.values()]
      .every(player => player.submitted);

    if (!allSubmitted) {
      return callback?.({
        error: "Még nem válaszolt minden játékos."
      });
    }

    room.questionIndex++;

    if (room.questionIndex >= room.questions.length) {
      io.to(code).emit("game-finished");

      return callback?.({
        success: true,
        finished: true
      });
    }

    for (const player of room.players.values()) {
      player.submitted = false;
    }

    sendQuestion(code, room);

    callback?.({
      success: true
    });
  });

  // =====================================================
  // ONLINE RIVÁLIS 1v1
  // =====================================================

  // Szoba létrehozása
  socket.on("online-rival:create", (data, callback) => {
    data = data || {};

    if (!validateOnlineRivalQuestions(data.questions)) {
      return callback?.({
        error: "Érvénytelen vagy hiányzó kérdéssor."
      });
    }

    const code = getCode(onlineRivalRooms);

    const room = {
      host: socket.id,
      players: [{
        id: socket.id,
        name: String(data.name || "Játékos 1").trim().slice(0, 20),
        cups: 10,
        submitted: false,
        bets: null,
        effects: {
          blind: false,
          timer: false,
          block5050: false
        },
        activeSteal: false,
        pendingSteal: false,
        usedSabotages: [],
        timer: null
      }],
      questions: JSON.parse(JSON.stringify(data.questions)),
      questionIndex: 0,
      started: false,
      resolved: false
    };

    onlineRivalRooms.set(code, room);

    socket.join(code);
    socket.data.onlineRivalCode = code;

    callback?.({
      success: true,
      code,
      players: getOnlineRivalPublicPlayers(room)
    });
  });

  // Csatlakozás hatjegyű kóddal
  socket.on("online-rival:join", (data, callback) => {
    data = data || {};

    const code = String(data.code || "").trim();
    const room = onlineRivalRooms.get(code);

    if (!room) {
      return callback?.({
        error: "Nem található ilyen szoba."
      });
    }

    if (room.started) {
      return callback?.({
        error: "A játék már elkezdődött."
      });
    }

    if (room.players.length >= 2) {
      return callback?.({
        error: "Ez a szoba már megtelt."
      });
    }

    const player = {
      id: socket.id,
      name: String(data.name || "Játékos 2").trim().slice(0, 20),
      cups: 10,
      submitted: false,
      bets: null,
      effects: {
        blind: false,
        timer: false,
        block5050: false
      },
      activeSteal: false,
      pendingSteal: false,
      usedSabotages: [],
      timer: null
    };

    room.players.push(player);

    socket.join(code);
    socket.data.onlineRivalCode = code;

    io.to(code).emit("online-rival:players", {
      players: getOnlineRivalPublicPlayers(room)
    });

    callback?.({
      success: true,
      code,
      players: getOnlineRivalPublicPlayers(room)
    });
  });

  // Játék indítása
  socket.on("online-rival:start", (callback) => {
    const code = socket.data.onlineRivalCode;
    const room = onlineRivalRooms.get(code);

    if (!room || room.host !== socket.id) {
      return callback?.({
        error: "Csak a szoba létrehozója indíthat."
      });
    }

    if (room.players.length !== 2) {
      return callback?.({
        error: "A játék indításához két játékos szükséges."
      });
    }

    if (room.started) {
      return callback?.({
        error: "A játék már elindult."
      });
    }

    room.started = true;
    room.questionIndex = 0;

    sendOnlineRivalQuestion(code, room);

    callback?.({
      success: true
    });
  });

  // Poharak beküldése
  socket.on("online-rival:submit", (data, callback) => {
    const code = socket.data.onlineRivalCode;
    const room = onlineRivalRooms.get(code);

    if (!room || !room.started || room.resolved) {
      return callback?.({
        error: "Nincs aktív válaszkör."
      });
    }

    const player = room.players.find(p => p.id === socket.id);

    if (!player || player.submitted) {
      return callback?.({
        error: "A válaszodat már beküldted."
      });
    }

    const bets = data && data.bets;

    if (
      !Array.isArray(bets) ||
      bets.length !== 4 ||
      !bets.every(n => Number.isInteger(n) && n >= 0) ||
      bets.reduce((a, b) => a + b, 0) !== player.cups
    ) {
      return callback?.({
        error: "Az összes megmaradt poharat el kell helyezned."
      });
    }

    player.bets = [...bets];
    player.submitted = true;

    if (player.timer) {
      clearTimeout(player.timer);
      player.timer = null;
    }

    io.to(code).emit("online-rival:submitted", {
      submittedCount: room.players.filter(p => p.submitted).length,
      totalPlayers: 2
    });

    callback?.({
      success: true
    });

    resolveOnlineRivalRound(code, room);
  });

  // Szabotázs aktiválása
  socket.on("online-rival:sabotage", (data, callback) => {
    const code = socket.data.onlineRivalCode;
    const room = onlineRivalRooms.get(code);

    if (!room || !room.started || room.resolved) {
      return callback?.({
        error: "Most nem használható szabotázs."
      });
    }

    const player = room.players.find(p => p.id === socket.id);
    const opponent = room.players.find(p => p.id !== socket.id);

    if (!player || !opponent || player.submitted) {
      return callback?.({
        error: "Most nem használhatod ezt a szabotázst."
      });
    }

    const type = String(data?.type || "");
    const allowed = ["blind", "timer", "block5050", "steal"];

    if (!allowed.includes(type)) {
      return callback?.({
        error: "Ismeretlen szabotázs."
      });
    }

    if (player.usedSabotages.includes(type)) {
      return callback?.({
        error: "Ezt a szabotázst már felhasználtad."
      });
    }

    player.usedSabotages.push(type);

    // Minden szabotázs a következő kérdésre érvényes
    if (type === "steal") {
      player.pendingSteal = true;
    } else {
      opponent.effects[type] = true;
    }

    io.to(code).emit("online-rival:sabotage-used", {
      playerName: player.name,
      type
    });

    callback?.({
      success: true,
      type
    });
  });

  // Következő kérdés
  socket.on("online-rival:next", (callback) => {
    const code = socket.data.onlineRivalCode;
    const room = onlineRivalRooms.get(code);

    if (!room || room.host !== socket.id) {
      return callback?.({
        error: "Csak a szoba létrehozója léptethet."
      });
    }

    if (!room.resolved) {
      return callback?.({
        error: "Még nem válaszolt mindkét játékos."
      });
    }

    room.questionIndex++;

    if (room.questionIndex >= room.questions.length) {
      io.to(code).emit("online-rival:finished", {
        players: getOnlineRivalPublicPlayers(room)
      });

      clearOnlineRivalTimers(room);
      onlineRivalRooms.delete(code);

      return callback?.({
        success: true,
        finished: true
      });
    }

    room.resolved = false;

    for (const player of room.players) {
      player.submitted = false;
      player.bets = null;
      player.activeSteal = false;
    }

    sendOnlineRivalQuestion(code, room);

    callback?.({
      success: true
    });
  });

  // Kilépés és kapcsolat megszakadása
  socket.on("disconnect", () => {

    // ONLINE RIVÁLIS kilépés
    const onlineCode = socket.data.onlineRivalCode;

    if (onlineCode) {
      const onlineRoom = onlineRivalRooms.get(onlineCode);

      if (onlineRoom) {
        clearOnlineRivalTimers(onlineRoom);

        io.to(onlineCode).emit("online-rival:opponent-left", {
          message: "Az ellenfeled kilépett a játékból."
        });

        onlineRivalRooms.delete(onlineCode);
      }
    }

    // RÉGI MULTIPLAYER kilépés – változatlan
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room) return;

    room.players.delete(socket.id);

    if (room.players.size === 0) {
      rooms.delete(code);
      return;
    }

    if (room.host === socket.id) {
      io.to(code).emit("room-error", {
        message: "A házigazda kilépett."
      });

      rooms.delete(code);
      return;
    }

    io.to(code).emit("player-left", {
      players: [...room.players.values()]
    });
  });

});

// RÉGI MULTIPLAYER – kérdésküldés
function sendQuestion(code, room) {
  const question = room.questions[room.questionIndex];

  const safeQuestion = { ...question };
  delete safeQuestion.correctIndex;

  io.to(code).emit("question", {
    index: room.questionIndex,
    total: room.questions.length,
    question: safeQuestion
  });
}

const PORT = process.env.PORT || 3000;

// Adatbázis inicializálása, majd szerverindítás
initializeDatabase()
  .then(() => {
    server.listen(PORT, () => {
      console.log("Szerver elindult a " + PORT + " porton.");
      console.log("Alkalmazás verzió: " + APP_VERSION_NAME);
      console.log("Minimális verzió: " + MIN_SUPPORTED_VERSION_CODE);
      console.log("Licencrendszer elindult.");
    });
  })
  .catch((error) => {
    console.error("Adatbázis inicializálási hiba:", error);
    process.exit(1);
  });
