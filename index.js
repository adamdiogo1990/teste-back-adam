const express = require('express');
const app = express();
const pg = require('pg');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const secret = 'mysecretkey';
const cors = require('cors');

app.use(bodyParser.json());
app.use(cors());

const pool = new pg.Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'postgres',
    password: 'postgres',
    port: 5432,
});

function generateJWT(payload) {
    const options = { expiresIn: '1h' }; // token expiration time
    return jwt.sign(payload, secret, options);
}

function verifyJWT(token) {
    return jwt.verify(token, secret);
}

app.post('/login', (req, res) => {
    console.log('req',req)
    const email = req.body.email;
    const password = req.body.password;
    pool.query('SELECT * FROM users WHERE email = $1 AND password = $2', [email, password], (error, result) => {
        if (error) {
            throw error;
        }
        if (result.rows.length > 0) {
            const token = generateJWT(result.rows[0]); // function to generate JWT
            res.json({ token });
        } else {
            res.status(401).json({ message: "Invalid credentials" });
        }
    });
});

app.get('/contacts', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: "Missing token" });
    }
    try {
        const decoded = verifyJWT(token); // function to verify JWT
        pool.query('SELECT * FROM contacts WHERE user_id = $1', [decoded.id], (error, result) => {
            if (error) {
                throw error;
            }
            res.status(200).json(result.rows);
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
});

app.get('/contact/:id', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: "Missing token" });
    }
    try {
        const id = req.params.id;
        const decoded = verifyJWT(token); // function to verify JWT
        pool.query('SELECT * FROM contacts WHERE id = $1', [id], (error, result) => {
            if (error) {
                throw error;
            }
            res.status(200).json(result.rows[0]);
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
});

app.post('/contacts', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: "Missing token" });
    }
    try {
        const decoded = verifyJWT(token);
        const name = req.body.name;
        const phone = req.body.phone;
        pool.query('INSERT INTO contacts (name, phone, user_id) VALUES ($1, $2, $3)', [name, phone, decoded.id], (error, result) => {
            if (error) {
                throw error;
            }
            res.status(201).json({ message: "Contact added successfully" });
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
});

app.put('/contacts/:id', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: "Missing token" });
    }
    try {
        const decoded = verifyJWT(token);
        const id = req.params.id;
        const name = req.body.name;
        const phone = req.body.phone;
        pool.query('UPDATE contacts SET name = $1, phone = $2 WHERE id = $3 AND user_id = $4', [name, phone, id, decoded.id], (error, result) => {
            if (error) {
                throw error;
            }
            res.status(200).json({ message: "Contact updated successfully" });
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
});

app.delete('/contacts/:id', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: "Missing token" });
    }
    try {
        const decoded = verifyJWT(token);
        const id = req.params.id;
        pool.query('DELETE FROM contacts WHERE id = $1 AND user_id = $2', [id, decoded.id], (error, result) => {
            if (error) {
                throw error;
            }
            res.status(200).json({ message: "Contact deleted successfully" });
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
});

app.listen(1000, () => {
    console.log('Server listening on port 1000');
});

