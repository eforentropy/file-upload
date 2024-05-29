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
/*
JWT_SECRET parametresi .env dosyası üzerinden elde edilmek zorundadır.
Hata alırsanız root path üzerinde .env dosyası oluşturup JWT_SECRET
değişkeni tanımlayabilirsiniz
*/

mongoose.connect('mongodb://localhost:27017/entropy', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err.message);
    });

const UserSchema = new mongoose.Schema({
    username: String,
    password: String
});

const LinkSchema = new mongoose.Schema({
    username: String,
    url: String,
    uploadDate: { type: Date, default: Date.now } // Yükleme tarihi alanı
});

const Link = mongoose.model('Link', LinkSchema);
const User = mongoose.model('User', UserSchema);

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'app')));
app.use(logRequests);


const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization;
    console.log(token);

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

app.post('/upload', authenticateJWT, upload.single('file'), async (req, res) => {
    if (req.file) {
        const fileName = req.file.filename;
        const username = req.user.username; 
        const url = process.env.PUBLIC_ADDR+'/uploads/' + fileName;
        const newLink = new Link({ username, url });
        await newLink.save();

        res.status(200).send(url);
    } else {
        res.sendStatus(400);
    }
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).send('Username already exist');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).send('User successfully registered');
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log(token)
        res.json({ token, username: user.username });
    } else {
        res.status(401).send('Invalid username or password');
    }
});

app.get('/user/uploads', authenticateJWT, async (req, res) => {
    try {
        const username = req.user.username;
        const userUploads = await Link.find({ username });
        console.log("SUCCESS");
        res.json(userUploads); // Dosya bilgilerini JSON formatında gönder
    } catch (error) {
        console.error('Error fetching user uploads:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/panel', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'app', 'panel.html'));
});
app.get('/myuploads', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, 'app', 'my-uploads.html'));
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});