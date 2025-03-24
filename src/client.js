var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _this = this;
// client.ts
var loginForm = document.getElementById("loginForm");
var chatBox = document.querySelector(".chat-container");
var loginBox = document.querySelector(".login-box");
var chatWindow = document.getElementById("chatWindow");
var sendBtn = document.getElementById("sendBtn");
var logoutBtn = document.getElementById("logoutBtn");
var username = "";
var socket;
loginForm.onsubmit = function (e) { return __awaiter(_this, void 0, void 0, function () {
    var password, res;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                e.preventDefault();
                username = document.getElementById("username").value;
                password = document.getElementById("password").value;
                return [4 /*yield*/, fetch("http://localhost:3000/login", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ username: username, password: password }),
                    })];
            case 1:
                res = _a.sent();
                if (res.ok) {
                    loginBox.style.display = "none";
                    chatBox.style.display = "block";
                    connectSocket();
                }
                else {
                    alert("Login failed");
                }
                return [2 /*return*/];
        }
    });
}); };
function connectSocket() {
    socket = new WebSocket("ws://localhost:3000");
    socket.onopen = function () {
        socket.send(JSON.stringify({ system: "user_connected", user: username }));
    };
    socket.onmessage = function (e) {
        var div = document.createElement("div");
        div.textContent = e.data;
        chatWindow.appendChild(div);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    };
    sendBtn.addEventListener("click", function () {
        var input = document.getElementById("messageInput");
        var to = prompt("Send to who?");
        if (input.value && to) {
            socket.send(JSON.stringify({ type: "chat", to: to, message: input.value }));
            input.value = "";
        }
    });
    logoutBtn.addEventListener("click", function () {
        socket.close();
        location.reload();
    });
}
