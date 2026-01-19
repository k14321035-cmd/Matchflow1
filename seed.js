if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// 1. Connection (Same as server.js)
const mongoURI = process.env.MONGO_URL || 'mongodb://localhost:27017/matchflow';
mongoose.connect(mongoURI);

const User = mongoose.model('User', {
    name: String,
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    interests: [String],
    bio: String,
    role: { type: String, default: 'user' }
});

async function seedDB() {
    try {
        // Clear existing users
        await User.deleteMany({});
        console.log("Database cleared.");

        const hashedPassword = await bcrypt.hash('password123', 10);

        const users = [
            {
                name: "Boss",
                email: "admin@matchflow.com",
                password: hashedPassword,
                role: "admin",
                interests: ["coding", "sushi", "hiking", "traveling"],
                bio: "The boss of MatchFlow."
            },
            {
                name: "Alice",
                email: "alice@example.com",
                password: hashedPassword,
                interests: ["coding", "sushi", "hiking", "gaming"], // High match with Boss
                bio: "Software engineer and sushi lover."
            },
            {
                name: "Bob",
                email: "bob@example.com",
                password: hashedPassword,
                interests: ["hiking", "traveling", "photography", "sushi"], // High match with Boss
                bio: "Adventure seeker."
            },
            {
                name: "Charlie",
                email: "charlie@example.com",
                password: hashedPassword,
                interests: ["cooking", "movies", "painting"], // Low match
                bio: "Just looking for friends."
            },
            {
                name: "Diana",
                email: "diana@example.com",
                password: hashedPassword,
                interests: ["coding", "sushi", "hiking", "traveling", "jazz"], // 100% match with Boss
                bio: "Life is a code."
            }
        ];

        await User.insertMany(users);
        console.log("Seed successful! Added 5 users.");
        process.exit();
    } catch (err) {
        console.log("Seed error:", err);
        process.exit(1);
    }
}

seedDB();

