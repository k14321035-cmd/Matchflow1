try {
    require('dotenv').config();
} catch (e) {
    // Skip dotenv in production if not installed
}
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const mongoURI = process.env.MONGO_URL || 'mongodb://mongo:27017/matchflow';
const PORT = process.env.PORT || 3000;

mongoose.connect(mongoURI).then(() => {
    console.log("Connected to MongoDB");
    initializeAdmin(); 
}).catch(err => console.error("Could not connect to MongoDB", err));

// 2. MODELS - Updated with 15 Personality Fields
const User = mongoose.model('User', {
    name: { type: String, required: true },
    gender: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    bio: { type: String, default: "" },
    interests: { type: [String], default: [] },
    hiddenMatches: { type: [mongoose.Schema.Types.ObjectId], default: [] },
    skippedMatches: { type: [{ userId: mongoose.Schema.Types.ObjectId, skippedAt: Date }], default: [] },
    // The 15 Data Points
    rhythm: String,        // morning/night
    planning: String,      // planner/flow
    social: String,        // butterfly/solo
    weekend: String,       // active/chill
    height: String,        // short/average/tall
    loveLanguage: String,  // touch/words/time/service/gifts
    depth: String,         // group/deep
    lesson: String,        
    showingLove: String,
    kids: String,          // yes/no/maybe
    niche: String,
    opinion: String,
    value: String,
    drainer: String,
    phone: String // Will store 'iphone' or 'samsung'
});

const Message = mongoose.model('Message', {
    senderId: String,
    receiverId: String,
    text: String,
    timestamp: { type: Date, default: Date.now },
    isRead: { type: Boolean, default: false }
});

async function initializeAdmin() {
    const adminEmail = process.env.ADMIN_EMAIL || 'k14321035@gmail.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Master';
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (!existingAdmin) {
        const hashedPassword = await bcrypt.hash(adminPassword, 10);
        await new User({
            name: 'Master Admin',
            email: adminEmail,
            password: hashedPassword,
            gender: 'male', // Required field satisfied
            role: 'admin',
            bio: 'System Administrator'
        }).save();
        console.log("Master Admin ready.");
    }
}




// 3. MIDDLEWARE
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'matchflow-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } 
}));
// NEW: Global Middleware for Notification Badge
// This prevents "unreadCount is undefined" errors on all pages
app.use(async (req, res, next) => {
    res.locals.unreadCount = 0;
    if (req.session.userId) {
        try {
            const count = await Message.countDocuments({ 
                receiverId: req.session.userId, 
                isRead: false 
            });
            res.locals.unreadCount = count;
        } catch (err) {
            console.error("Error fetching unread count");
        }
    }
    next();
});
app.post('/update-location', async (req, res) => {
    if (!req.session.userId) return res.sendStatus(401);
    const { lat, lng } = req.body;
    
    await User.findByIdAndUpdate(req.session.userId, {
        location: { type: "Point", coordinates: [lng, lat] }
    });
    res.sendStatus(200);
});
// 4. MAGNET MATCHING LOGIC (Internal Utility)
function getMagnetData(me, target) {
    let score = 0;
    let reasons = [];

    // A. FOUNDATIONAL ALIGNMENT (Similarity)
    if (me.kids === target.kids && me.kids !== 'maybe') {
        score += 25;
        reasons.push("You share the same vision for family 🏠");
    }
    if (me.loveLanguage === target.loveLanguage) {
        score += 25;
        reasons.push("You speak the same love language ❤️");
    }

    // B. MAGNET LIFESTYLE (Complementary Differences)
    if (me.rhythm !== target.rhythm && me.rhythm && target.rhythm) {
        score += 15;
        reasons.push("Your daily energies balance each other 🌓");
    }
    if (me.planning !== target.planning && me.planning && target.planning) {
        score += 15;
        const msg = me.planning === 'planner' ? "You'll provide the plan, they'll provide the fun 🌊" : "They'll provide the plan, you'll provide the adventure 🌊";
        reasons.push(msg);
    }
    if (me.social !== target.social && me.social && target.social) {
        score += 10;
        reasons.push("A perfect mix of social life and solo peace 🧘");
    }

    // C. SHARED INTERESTS
    const common = (me.interests || []).filter(i => (target.interests || []).includes(i));
    if (common.length > 0) {
        score += (common.length * 5);
        reasons.push(`Shared love for ${common[0]}! ✨`);
    }

    if (me.phone === target.phone && me.phone) {
        score += 5;
        // Optional: Add a funny reason if they match
        if (reasons.length < 2) {
            const phoneBrand = me.phone === 'iphone' ? 'iMessage' : 'Android';
            reasons.push(`Same ecosystem! Both on ${phoneBrand} 📱`);
        }
    }
    
    return {
        score: Math.min(score, 100),
        reason: reasons[0] || "A unique connection waiting to be explored..."
    };
}
app.post('/unmatch/:id', async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Login required");
    console.log(`Unmatch request for: ${req.params.id} from user: ${req.session.userId}`);

    try {
        const targetId = new mongoose.Types.ObjectId(req.params.id);
        await User.findByIdAndUpdate(req.session.userId, {
            $addToSet: { hiddenMatches: targetId }
        });
        console.log(`Unmatch successful for ${targetId}, redirecting...`);
        res.redirect('/'); 
    } catch (err) {
        console.error("Unmatch error:", err);
        res.status(500).send("Error removing match");
    }
});;
// 
//5. MAIN USER ROUTES
app.get('/', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    try {
        const me = await User.findById(req.session.userId);
        if (!me) return res.redirect('/logout');
        if (me.role === 'admin') return res.redirect('/admin');
        
        // 1. Safety Checks
        if (!me.gender) return res.redirect('/edit-profile'); 
        if (!me.rhythm) return res.redirect('/register1');

        // 2. The Gender Filter
        const targetGender = (me.gender === 'male') ? 'female' : 'male';

        // 3. Database Query: Get all potential opposite-gender users
       // THE NEW SEARCH: Includes the 5km Radius
       const hasLocation = me.location && me.location.coordinates && me.location.coordinates.length === 2;

const searchCriteria = {
    _id: { $ne: me._id },
    role: { $ne: 'admin' },
    gender: targetGender,
    rhythm: { $exists: true }
};

// 2. Only add the 5km math if the user HAS coordinates
if (hasLocation && me.location.coordinates[0] !== 0) {
    searchCriteria.location = {
        $near: {
            $geometry: {
                type: "Point",
                coordinates: me.location.coordinates
            },
            $maxDistance: 5000 
        }
    };
}

let potentialMatches = await User.find(searchCriteria);
        // 4. Identify who is currently "skipped"
        // Ensure you use 'skippedMatches' consistently in your Schema
        const skippedIds = (me.skippedMatches || []).map(s => s.userId.toString());
        
        // 5. Filter for people NOT skipped
        let availableMatches = potentialMatches.filter(u => !skippedIds.includes(u._id.toString()));

        let timeLeft = 0; // Initialize for the loading bar

        // 6. ROTATION LOGIC: If no fresh matches left...
        if (availableMatches.length === 0 && potentialMatches.length > 0) {
            
            if (potentialMatches.length === 1) {
                // RULE: If only 1 person exists, check if 10 mins passed
                const lastSkipObj = me.skippedMatches[0];
                const waitTime = 10 * 60 * 1000; // 10 mins in ms
                const elapsed = new Date() - new Date(lastSkipObj.skippedAt);
                
                if (elapsed >= waitTime) {
                    // Time is up! Clear skips to show them again
                    await User.findByIdAndUpdate(me._id, { $set: { skippedMatches: [] } });
                    availableMatches = potentialMatches;
                } else {
                    // Still waiting... calculate remaining time for the bar
                    timeLeft = waitTime - elapsed;
                }
            } else {
                // RULE: If multiple people exist, just rotate immediately back to the start
                await User.findByIdAndUpdate(me._id, { $set: { skippedMatches: [] } });
                availableMatches = potentialMatches;
            }
        }

        // 7. Run compatibility math on the available ones
        const matchesWithData = availableMatches.map(user => {
            const magnet = getMagnetData(me, user);
            return { 
                ...user._doc, 
                score: magnet.score, 
                matchReason: magnet.reason 
            };
        })
        .filter(u => u.score >= 50) // Keep your minimum compatibility filter
        .sort((a, b) => b.score - a.score);

        // 8. Render the page with the calculation results
        res.render('index', { 
            me, 
            matches: matchesWithData, 
            timeLeft: timeLeft 
        });

    } catch (err) {
        console.error("Dashboard Error:", err);
        res.status(500).send("Error loading dashboard.");
    }
});

app.post('/unmatch/:id', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    try {
        // Use 'skippedMatches' with the userId and current timestamp
        await User.findByIdAndUpdate(req.session.userId, {
            $addToSet: { 
                skippedMatches: { 
                    userId: req.params.id, 
                    skippedAt: new Date() 
                } 
            }
        });

        res.redirect('/'); 
    } catch (err) {
        console.error("Unmatch error:", err);
        res.status(500).send("Could not remove match.");
    }
});
// 6. PROFILE UPDATES
app.get('/register1', async (req, res) => {
    if (!req.session.userId) return res.redirect('/register');
    const user = await User.findById(req.session.userId);
    res.render('register1', { user });
});

app.post('/register1', async (req, res) => {
    const data = req.body;
    if (data.interests) {
        data.interests = data.interests.split(',').map(i => i.trim().toLowerCase()).filter(i => i !== "");
    }
    await User.findByIdAndUpdate(req.session.userId, data);
    res.redirect('/');
});

app.get('/edit-profile', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const user = await User.findById(req.session.userId);
    res.render('edit-profile', { user });
});

app.post('/edit-profile', async (req, res) => {
    const data = req.body;
    if (data.interests) {
        data.interests = data.interests.split(',').map(i => i.trim().toLowerCase()).filter(i => i !== "");
    }
    await User.findByIdAndUpdate(req.session.userId, data);
    res.redirect('/');
});


// 7. INBOX & MESSAGES
app.get('/messages', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    try {
        const me = await User.findById(req.session.userId);
        const myMessages = await Message.find({
            $or: [{ senderId: me._id.toString() }, { receiverId: me._id.toString() }]
        }).sort({ timestamp: -1 });

        const chattedUserIds = [...new Set(myMessages.map(m => 
            m.senderId === me._id.toString() ? m.receiverId : m.senderId
        ))];

        const chatPartners = await User.find({ _id: { $in: chattedUserIds } });
        res.render('messages', { me, chatPartners });
    } catch (err) {
        res.status(500).send("Error loading messages.");
    }
});

// 8. CHAT INTERFACE
app.get('/chat/:targetId', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const me = await User.findById(req.session.userId);
    const target = await User.findById(req.params.targetId);
    
    const history = await Message.find({
        $or: [
            { senderId: me._id.toString(), receiverId: target._id.toString() },
            { senderId: target._id.toString(), receiverId: me._id.toString() }
        ]
    }).sort({ timestamp: 1 }).limit(50);

    res.render('chat', { me, target, history });
});

// 9. AUTHENTICATION
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user._id;
        return res.redirect('/');
    }
    res.send('Invalid credentials. <a href="/login">Try again</a>');
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    // 1. You MUST add lat and lng here
    const { name, email, password, gender, lat, lng } = req.body; 
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({ 
        name, 
        email, 
        password: hashedPassword, 
        gender: gender, 
        role: 'user',
        // 2. Now parseFloat(lng) and parseFloat(lat) will work correctly
        location: {
            type: "Point",
            coordinates: [parseFloat(lng) || 0, parseFloat(lat) || 0] 
        }
    });
    
    await newUser.save();
    req.session.userId = newUser._id;
    res.redirect('/register1'); 
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/login'); });
});

// 10. ADMIN DASHBOARD
app.get('/admin', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const me = await User.findById(req.session.userId);
    if (me?.role !== 'admin') return res.status(403).send("Forbidden");
    const users = await User.find({ role: 'user' });
    res.render('admin', { users, me });
});
app.post('/admin/add-user', async (req, res) => {
    // 1. Security Check
    const me = await User.findById(req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).send("Unauthorized");

    try {
        const { name, email, password, gender, role } = req.body;
        
        // 2. Hash the password for the new user
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Create and Save
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            gender,
            role: role || 'user',
            interests: [],
            bio: ""
        });

        await newUser.save();
        res.redirect('/admin'); // Redirect back to dashboard to see the new user
    } catch (err) {
        console.error(err);
        if (err.code === 11000) {
            res.status(400).send("Error: This email is already registered.");
        } else {
            res.status(500).send("Error creating user: " + err.message);
        }
    }
});
app.get('/admin/edit/:id', async (req, res) => {
    // 1. Security Check: Only admins allowed
    if (!req.session.userId) return res.redirect('/login');
    const me = await User.findById(req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).send("Unauthorized");

    try {
        // 2. Find the user being edited
        const targetUser = await User.findById(req.params.id);
        if (!targetUser) return res.status(404).send("User not found");

        // 3. Render a page (we'll reuse your edit-profile or a new admin-edit)
        res.render('admin-edit', { user: targetUser });
    } catch (err) {
        res.status(500).send("Error loading user data");
    }
});
app.post('/admin/edit/:id', async (req, res) => {
    // Security Check
    const me = await User.findById(req.session.userId);
    if (!me || me.role !== 'admin') return res.status(403).send("Unauthorized");

    try {
        const updateData = req.body;
        
        // Handle interests if they come in as a string
        if (updateData.interests) {
            updateData.interests = updateData.interests.split(',').map(i => i.trim());
        }

        await User.findByIdAndUpdate(req.params.id, updateData);
        res.redirect('/admin'); // Go back to admin dashboard after saving
    } catch (err) {
        res.status(500).send("Failed to update user");
    }
});

app.post('/admin/delete/:id', async (req, res) => {
    const me = await User.findById(req.session.userId);
    if (me?.role === 'admin') await User.findByIdAndDelete(req.params.id);
    res.redirect('/admin');
});

// 11. SOCKET.IO
io.on('connection', (socket) => {
    // Users should join a room named after their UserId for private notifications
    /*socket.on('join-notifications', (userId) => {
        socket.join(userId);
    });*/
    socket.on('join-room', (roomId) => {
        socket.leaveAll(); // Optional: leaves previous chat rooms
        socket.join(roomId);
        console.log(`User joined room: ${roomId}`);
    });

    socket.on('send-chat-message', async (data) => {
        const newMessage = new Message({
            senderId: data.senderId,
            receiverId: data.receiverId,
            text: data.message,
            isRead: false // Important for the badge count
        });
        await newMessage.save();

        // 1. Send the message to the chat room
        io.to(data.roomId).emit('receive-message', {
            text: data.message,
            senderId: data.senderId
        });

        // 2. Alert the receiver's private room for the notification badge
        io.to(data.receiverId).emit('new-notification', {
            fromName: data.senderName // Optional: to show a toast/alert
        });
    });
});

server.listen(PORT, () => console.log(`MatchFlow live at port ${PORT}`));




