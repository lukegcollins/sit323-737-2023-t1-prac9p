const express = require('express');
const app = express();
const port = 3000;
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');

// Authentication server private key for token generation (tokens to be verified by passport service using paired public key)
const fs = require('fs');
const PRIVATE_KEY = fs.readFileSync('./rsa_private.pem', 'utf8');
const crypto = require('crypto');

const uri = "mongodb://admin:password@mongo-svc";

const client = new MongoClient(uri, {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true
	}
});
const myDB = client.db("user");
const myColl = myDB.collection("users");

async function registerUser(req, res){
	try {
		let salt = crypto.randomBytes(32).toString('hex');
		let hashedPassword = crypto.pbkdf2Sync(req.body.password, salt, 10000, 64, 'sha512').toString('hex');
		
		const result = await myColl.updateOne({ username: req.body.username },{ $setOnInsert: {username: req.body.username, hashedPassword: hashedPassword, salt: salt, access: 0b1111 } }, { upsert: true });

		if(result.upsertedId == null) res.status(401).json({ status: 401, message: "Registration Failure: User already exists" });
		res.status(200).json({ status: 200, message: "Registration successful" });
	}catch(e){
		console.log(e.message);
	}
}

async function updatePassword(req, res){
	try {		
		let result = await myColl.findOne({ username: req.body.username });
		if (result == null) res.status(401).json({ status: 401, message: "Error: Invalid credentials" });
		
		let hashedPassword = crypto.pbkdf2Sync(req.body.password, result.salt, 10000, 64, 'sha512').toString('hex');
		if (hashedPassword !== result.hashedPassword) res.status(401).json({ status: 401, message: "Error: Invalid credentials" });
		else{
			let salt = crypto.randomBytes(32).toString('hex');
			let newHashedPassword = crypto.pbkdf2Sync(req.body.newpass, salt, 10000, 64, 'sha512').toString('hex');
			result = await myColl.updateOne({ username: req.body.username },{ $set: {username: req.body.username, hashedPassword: newHashedPassword, salt: salt } });
			res.status(200).json({ status: 200, message: "Password Updated" });
		}
	}catch(e){
		console.log(e.message);
	}
}

// Simple delete with no validity checks
async function deleteUser(req, res){
	try {		
		const result = await myColl.deleteOne({ username: req.body.username });

		if(result.deletedCount > 0) res.status(200).json({ status: 200, message: "Delete successful" });
		res.status(401).json({ status: 401, message: "Delete Failure: User not found" });
	}catch(e){
		console.log(e.message);
	}
}

async function loginUser(req, res){
	try{
		let result = await myColl.findOne({ username: req.body.username });
		if (result == null) res.status(401).json({ status: 401, message: "Error: Invalid credentials" });
		
		let hashedPassword = crypto.pbkdf2Sync(req.body.password, result.salt, 10000, 64, 'sha512').toString('hex');
		if (hashedPassword !== result.hashedPassword) res.status(401).json({ status: 401, message: "Error: Invalid credentials" });

		// Token expires in 1 hour
		const expiresIn = '1h';

		const payload = {
			sub: { username: req.body.username, access: result.access }
		};

		const token = jwt.sign(payload, PRIVATE_KEY, { expiresIn: expiresIn, algorithm: 'RS256' });
		res.status(200).json({ status: 200, username: req.body.username, token: token, expiresIn: expiresIn });
	}catch(e){
		console.log(e.message);
	}
}

async function connectMongoDB(){
	try {
		await client.connect();
		await client.db("admin").command({ ping: 1 });
	}catch(e){
		console.log(e.message);
	}
}
connectMongoDB().catch(console.dir);


app.use(express.json());
app.use((err, req, res, next) => {
    res.status(400).json({ status: 400, message: "Invalid JSON format" })
});

app.post('/register', (req, res) => {
    registerUser(req, res);
});

app.post('/changepass', (req, res) => {
	updatePassword(req, res);
});

app.post('/deleteuser', (req, res) => {
	deleteUser(req, res);
});

app.post('/login', (req, res) => {
    loginUser(req, res);
});

app.use((req, res) => {
    res.sendStatus(404);
});

app.listen(port, () => console.log('listening on port:' + port));