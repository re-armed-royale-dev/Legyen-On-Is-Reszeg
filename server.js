
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(express.json({ limit: "2mb" }));
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

const shares = new Map();
const rooms = new Map();

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

app.get("/", (req, res) => {
  res.send("Legyen Ön is Részeg – szerver működik! 🍻");
});

// Kérdéssor megosztása
app.post("/api/share", (req, res) => {
  const { questions } = req.body;

  if (!Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: "Érvénytelen kérdéssor." });
  }

  if (questions.length > 500) {
    return res.status(400).json({ error: "Túl sok kérdés." });
  }

  const code = getCode(shares);
  shares.set(code, {
    questions,
    createdAt: Date.now()
  });

  res.json({ success: true, code });
});

// Kérdéssor letöltése kód alapján
app.get("/api/share/:code", (req, res) => {
  const item = shares.get(req.params.code);

  if (!item) {
    return res.status(404).json({ error: "Ismeretlen kód." });
  }

  res.json({
    success: true,
    questions: item.questions
  });
});

// Multiplayer
io.on("connection", (socket) => {

  // Szoba létrehozása
  socket.on("create-room", (data, callback) => {
    const questions = data && data.questions;

    if (!Array.isArray(questions) || questions.length === 0) {
      return callback?.({ error: "Nincs kérdéssor." });
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
    const code = String(data.code || "");
    const room = rooms.get(code);

    if (!room) {
      return callback?.({ error: "Nem található ilyen szoba." });
    }

    if (room.started) {
      return callback?.({ error: "A játék már elkezdődött." });
    }

    if (room.players.size >= 8) {
      return callback?.({ error: "A szoba megtelt." });
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

    callback?.({ success: true, code });
  });

  // Játék indítása
  socket.on("start-game", (callback) => {
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room || room.host !== socket.id) {
      return callback?.({ error: "Csak a szoba létrehozója indíthat." });
    }

    room.started = true;
    room.questionIndex = 0;

    sendQuestion(code, room);
    callback?.({ success: true });
  });

  // Válasz elküldése
  socket.on("submit-answer", (data, callback) => {
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room || !room.started) {
      return callback?.({ error: "Nincs aktív játék." });
    }

    const player = room.players.get(socket.id);
    if (!player || player.submitted) {
      return callback?.({ error: "Már elküldted a válaszod." });
    }

    const bets = data && data.bets;

    if (
      !Array.isArray(bets) ||
      bets.length !== 4 ||
      !bets.every(n => Number.isInteger(n) && n >= 0) ||
      bets.reduce((a, b) => a + b, 0) !== 10
    ) {
      return callback?.({ error: "Pontosan 10 poharat kell elhelyezned." });
    }

    const question = room.questions[room.questionIndex];
    const correctIndex = Number(question.correctIndex);

    if (
      !Number.isInteger(correctIndex) ||
      correctIndex < 0 ||
      correctIndex > 3
    ) {
      return callback?.({ error: "Hibás kérdésadat." });
    }

    const correctGlasses = bets[correctIndex];

    player.submitted = true;

    // Az eredményt csak az adott játékos kapja meg
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

    callback?.({ success: true });
  });

  // Következő kérdés
  socket.on("next-question", (callback) => {
    const code = socket.data.roomCode;
    const room = rooms.get(code);

    if (!room || room.host !== socket.id) {
      return callback?.({ error: "Csak a házigazda léptethet." });
    }

    const allSubmitted = [...room.players.values()]
      .every(player => player.submitted);

    if (!allSubmitted) {
      return callback?.({ error: "Még nem válaszolt minden játékos." });
    }

    room.questionIndex++;

    if (room.questionIndex >= room.questions.length) {
      io.to(code).emit("game-finished");
      return callback?.({ success: true, finished: true });
    }

    for (const player of room.players.values()) {
      player.submitted = false;
    }

    sendQuestion(code, room);
    callback?.({ success: true });
  });

  // Kilépés
  socket.on("disconnect", () => {
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

function sendQuestion(code, room) {
  const question = room.questions[room.questionIndex];

  // A helyes válasz indexét nem küldjük el a játékosoknak
  const safeQuestion = { ...question };
  delete safeQuestion.correctIndex;

  io.to(code).emit("question", {
    index: room.questionIndex,
    total: room.questions.length,
    question: safeQuestion
  });
}

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log("Szerver elindult a " + PORT + " porton.");
});
