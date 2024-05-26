const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');
const multer = require('multer');



const logRequests = (req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.url}`);
    next(); 
};


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    }
  });

dotenv.config();
const upload = multer({ storage: storage });
const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect('mongodb://localhost:27017/myapp', { useNewUrlParser: true, useUnifiedTopology: true });

const UserSchema = new mongoose.Schema({
    username: String,
    password: String
});

const User = mongoose.model('User', UserSchema);

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'app')));
app.use(logRequests);

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization;

    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};



app.post('/logout', (req, res) => {
    res.sendStatus(200);
});



app.post('/upload', upload.single('file'), (req, res) => {
    if (req.file) {
        const fileName = req.file.filename;
        res.status(200).send('https://127.0.0.1/uploads/' + fileName);  
        
    } else {
        res.sendStatus(400);
    }
});


app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).send('User registered successfully');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, username: user.username });
    } else {
        res.status(401).send('Invalid username or password');
    }
});
app.get('/panel', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'app', 'panel.html'));
});

app.get('/success', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'app', 'success.html'));
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});