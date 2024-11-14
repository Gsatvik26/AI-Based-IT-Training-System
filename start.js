const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const natural = require('natural');

const app = express();
const port = 8080;

// Create a connection pool for MySQL
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'tiger',
    database: 'mini_project'
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.use(express.static(path.join(__dirname, 'public')));

// User registration route
app.post('/register', (req, res) => {
    const { username, password, role } = req.body; // Role can be 'admin' or 'user'

    // Check if the role is either 'admin' or 'user'
    if (role !== 'admin' && role !== 'user') {
        return res.status(400).send('Invalid role. Role must be "admin" or "user".');
    }

    // Check if the user already exists in the appropriate table
    const table = role === 'admin' ? 'admin' : 'users';
    pool.query(`SELECT * FROM ${table} WHERE username = ?`, [username], (err, result) => {
        if (err) {
            return res.status(500).send('Server error: ' + err.message);
        }
        if (result.length > 0) {
            return res.status(400).send('User already exists');
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).send('Server error: ' + err.message);
            }

            // Insert the new user into the appropriate table
            const sql = `INSERT INTO ${table} (username, password) VALUES (?, ?)`;
            pool.query(sql, [username, hash], (err, result) => {
                if (err) {
                    return res.status(500).send('Server error: ' + err.message);
                }
                res.send(`${role.charAt(0).toUpperCase() + role.slice(1)} registered successfully`);
            });
        });
    });
});

// User login route
app.post('/login', (req, res) => {
    const { username, password, loginType } = req.body;

    let table = 'users'; // Default to 'users' table
    if (loginType === 'admin') {
        table = 'admin'; // Assuming 'admin' is a separate table in your database
    }

    // Query the database based on the selected login type (admin or user)
    pool.query(`SELECT * FROM ${table} WHERE username = ?`, [username], (err, result) => {
        if (err) {
            return res.status(500).send('Server error: ' + err.message);
        }
        if (result.length === 0) {
            return res.status(400).send('User does not exist');
        }

        bcrypt.compare(password, result[0].password, (err, match) => {
            if (err) {
                return res.status(500).send('Server error: ' + err.message);
            }
            if (!match) {
                return res.status(400).send('Incorrect password');
            }

            req.session.user = result[0];
            if (loginType === 'admin') {
                res.redirect('/admin-dashboard.html'); // Redirect to Admin Dashboard
            } else {
                res.redirect('/user-dashboard.html'); // Redirect to User Dashboard
            }
        });
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Server error: ' + err.message);
        }
        res.redirect('/login.html');
    });
});

// Check if the user is authenticated
app.get('/checkAuth', (req, res) => {
    if (req.session.user) {
        res.sendStatus(200);
    } else {
        res.sendStatus(401);
    }
});

// CRUD operations for Admin
app.get('/users', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).send('Unauthorized');
    }
    pool.query('SELECT id, username, role FROM users', (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// Create a new user
app.post('/users', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).send('Unauthorized');
    }
    const { username, password, role } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        pool.query(sql, [username, hash, role], (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: 'User created successfully', userId: result.insertId });
        });
    });
});

// Update user
app.put('/users/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.params.id;
    const { username, password, role } = req.body;

    // Prepare query to update user details
    let sql = 'UPDATE users SET ';
    let values = [];

    if (username) {
        sql += 'username = ?, ';
        values.push(username);
    }
    if (password) {
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            sql += 'password = ?, ';
            values.push(hash);
        });
    }
    if (role) {
        sql += 'role = ?, ';
        values.push(role);
    }

    // Remove the trailing comma
    sql = sql.slice(0, -2);
    sql += ' WHERE id = ?';
    values.push(userId);

    pool.query(sql, values, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json({ message: 'User updated successfully' });
    });
});



// Delete a user
app.delete('/users/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).send('Unauthorized');
    }
    const { id } = req.params;
    pool.query('DELETE FROM users WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    });
});

// Routes for the front-end pages
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/admin-dashboard.html', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/user-dashboard.html', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'user') {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});

// // Endpoint to save assessment results
// app.post('/submit-assessment', (req, res) => {
//     const { userId, courseId, mcqScore, descriptiveScore, totalScore } = req.body;

//     const query = `
//         INSERT INTO assessments_scores (user_id, course_id, mcq_score, descriptive_score, total_score)
//         VALUES (?, ?, ?, ?, ?)
//     `;
//     db.query(query, [userId, courseId, mcqScore, descriptiveScore, totalScore], (err, result) => {
//         if (err) {
//             return res.status(500).json({ message: 'Error saving the results', error: err });
//         }
//         res.status(200).json({ message: 'Assessment results saved successfully' });
//     });
// });

app.get('/api/courses', (req, res) => {
    const query = `
        SELECT c.id AS course_id, c.title AS course_title, v.id AS video_id, v.title AS video_title, v.video_url
        FROM courses c
        LEFT JOIN videos v ON c.id = v.course_id
    `;
    db.query(query, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const courses = rows.reduce((acc, row) => {
            let course = acc.find(c => c.id === row.course_id);
            if (!course) {
                course = { id: row.course_id, title: row.course_title, videos: [] };
                acc.push(course);
            }
            course.videos.push({ id: row.video_id, title: row.video_title, video_url: row.video_url });
            return acc;
        }, []);
        res.json(courses);
    });
});

// Mark video as watched and check if all videos watched
app.post('/api/mark-watched', (req, res) => {
    const { videoId, courseId } = req.query;
    // Assume tracking watched videos in a table called `user_watched_videos`
    // Implement logic to mark the video as watched for the user
    // Check if all videos in course are watched, then respond with { allVideosWatched: true }
});

// Define a list of tech-related questions and answers
const qaList = [
    { question: "What is AI?", answer: "AI stands for Artificial Intelligence, which refers to the simulation of human intelligence in machines." },
    { question: "What is machine learning?", answer: "Machine learning is a subset of AI that enables systems to learn from data and improve over time." },
    { question: "What is deep learning?", answer: "Deep learning is a class of machine learning that uses neural networks with many layers to analyze various factors of data." },
    { question: "What is blockchain?", answer: "Blockchain is a distributed ledger technology that ensures transparency and security in transactions." },
    { question: "What is cloud computing?", answer: "Cloud computing provides on-demand availability of computer system resources, especially data storage and computing power." },
    { question: "What is the Internet of Things (IoT)?", answer: "IoT refers to the interconnected network of devices that communicate and exchange data with each other." },
    // Add more questions and answers here
];

    
    // AI Chatbot endpoint
    app.post('/api/chat', (req, res) => {
        const userMessage = req.body.message.toLowerCase(); // Normalize user input

        // Find a matching question
        const match = qaList.find(qa => userMessage.includes(qa.question.toLowerCase()));

        if (match) {
            res.json({ reply: match.answer });
        } else {
            res.json({ reply: "Sorry, I don't have an answer for that. Please ask another question!" });
        }
    });

// Define the correct MCQ answer
const correctMCQAnswer = "A";  // This is just an example, can be dynamic as well.

// Reference answers for descriptive evaluation (can be improved with more sophisticated answers)
const referenceAnswers = [
  "AI is the simulation of human intelligence in machines that are programmed to think like humans and mimic their actions.",
  "Machine learning is a branch of AI that enables systems to learn from data and improve without being explicitly programmed.",
  "Automation refers to using technology to perform tasks with minimal human intervention.",
  "Data science is an interdisciplinary field that uses scientific methods, processes, algorithms, and systems to extract knowledge and insights from structured and unstructured data."
];

// List of common negation words
const negationWords = ['not', 'no', 'never', 'none', 'nothing', 'nobody', 'nowhere', 'neither', 'nor'];

// Function to check for negation words
function containsNegation(text) {
  const lowerText = text.toLowerCase();
  return negationWords.some(word => lowerText.includes(word));
}

// Function to evaluate MCQ
function evaluateMCQ(answer) {
  let score = answer === correctMCQAnswer ? 10 : 0;  // Assign full marks if correct, 0 if incorrect

  // Check for negation in MCQ answer and reduce score if found
  if (containsNegation(answer)) {
    score = Math.max(0, score - 2); // Reduce marks by 2 if negation is found, but ensure score doesn't go below 0
  }

  return score;
}

// Cosine Similarity Function (with Natural.js)
function cosineSimilarity(v1, v2) {
  const dotProduct = v1.reduce((sum, val, idx) => sum + val * v2[idx], 0);
  const magnitudeA = Math.sqrt(v1.reduce((sum, val) => sum + val * val, 0));
  const magnitudeB = Math.sqrt(v2.reduce((sum, val) => sum + val * val, 0));
  return dotProduct / (magnitudeA * magnitudeB);
}

// Function to evaluate descriptive answer using Cosine Similarity (Basic NLP)
function evaluateDescriptive(answer) {
  const tfidf = new natural.TfIdf();
  
  // Add reference answers to the tf-idf model
  referenceAnswers.forEach(refAnswer => {
    tfidf.addDocument(refAnswer);
  });
  
  // Tokenize and process the student's answer
  tfidf.addDocument(answer);

  // Get the cosine similarity score between the student's answer and reference answers
  let maxScore = 0;
  tfidf.listTerms(1).forEach((term, index) => {
    const score = tfidf.tfidf(term.term, 0);
    maxScore = Math.max(maxScore, score);
  });

  // Normalize score between 0 and 10
  let finalScore = Math.min(maxScore * 5, 10);  // Normalize to a 0-10 scale

  // Check for negation in descriptive answer and reduce score if found
  if (containsNegation(answer)) {
    finalScore = Math.max(0, finalScore - 2);  // Reduce marks by 2 if negation is found
  }

  return finalScore;
}

// Function to evaluate descriptive answer using BERT embeddings (via TensorFlow.js)
async function evaluateDescriptiveBERT(answer) {
  const model = await use.load();
  const referenceEmbeddings = await model.embed(referenceAnswers);
  const studentEmbedding = await model.embed([answer]);

  // Calculate cosine similarity between the student's answer and the reference answers
  const similarities = [];
  referenceEmbeddings.arraySync().forEach((refEmbedding, index) => {
    const similarity = cosineSimilarity(refEmbedding, studentEmbedding.arraySync()[0]);
    similarities.push(similarity);
  });

  // Get the best match similarity
  const maxSimilarity = Math.max(...similarities);
  
  // Normalize to a score between 0 and 10
  let finalScore = maxSimilarity * 10;  // Normalize to a 0-10 scale

  // Check for negation in descriptive answer and reduce score if found
  if (containsNegation(answer)) {
    finalScore = Math.max(0, finalScore - 2);  // Reduce marks by 2 if negation is found
  }

  return finalScore;
}

// Endpoint to submit assessment marks
app.post('/submit-assessment', async (req, res) => {
  const { mcqAnswer, descriptiveAnswer, useBERT } = req.body;

  if (mcqAnswer === undefined || descriptiveAnswer === undefined) {
    return res.status(400).send('Missing required fields');
  }

  // Evaluate MCQ and Descriptive Answer
  const mcqScore = evaluateMCQ(mcqAnswer);
  let descriptiveScore = 0;

  if (useBERT) {
    // If user wants BERT-based evaluation
    descriptiveScore = await evaluateDescriptiveBERT(descriptiveAnswer);
  } else {
    // Else use Cosine Similarity-based evaluation
    descriptiveScore = evaluateDescriptive(descriptiveAnswer);
  }

  const totalScore = mcqScore + descriptiveScore;

  // Insert assessment marks into the database
  const query = `
    INSERT INTO assessments1 (mcq_answer, descriptive_answer, mcq_score, descriptive_score, total_score, evaluation_status)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  pool.query(query, [mcqAnswer, descriptiveAnswer, mcqScore, descriptiveScore, totalScore, 'Evaluated'], (err, result) => {
    if (err) {
      console.error('Error saving assessment:', err);
      return res.status(500).send('Error saving the assessment');
    }
    res.status(200).send('Assessment saved and evaluated successfully');
  });
});

app.get("/get-assessment-scores", (req, res) => {
    pool.query("SELECT mcq_score, descriptive_score, total_score FROM assessments WHERE id = 2", (err, result) => {
      if (err) throw err;
      res.json(result[0]); // Send the first result
    });
  });


app.get('/assessments1', (req, res) => {
    pool.query('SELECT * FROM assessments1', (err, results) => {
      if (err) {
        console.error('Error fetching assessments:', err);
        return res.status(500).send('Error fetching assessments');
      }
    //   console.log('Assessments:', results);  // Log the results
      res.json(results);
    });
  });
  // DELETE request to delete an assessment by ID
app.delete('/assessments1/:id', (req, res) => {
    const assessmentId = req.params.id;

    // SQL query to delete the assessment
    const query = 'DELETE FROM assessments1 WHERE id = ?';

    // Execute the query
    pool.query(query, [assessmentId], (err, results) => {
        if (err) {
            console.error('Error deleting assessment:', err);
            return res.status(500).send('Error deleting assessment');
        }
        console.log('Assessment deleted:', results);
        res.status(200).send('Assessment deleted successfully');
    });
});

// app.get("/get-marks", async (req, res) => {
//     try {
//       // Updated table name to `assessments1`
//       const result = await pool.execute("SELECT total_score FROM assessments1 ORDER BY id DESC LIMIT 1");
  
//       const rows = Array.isArray(result) && result[0] ? result[0] : [];
      
//       if (rows.length > 0) {
//         const totalMarks = rows[0].total_score;
//         res.json({ totalMarks });
//       } else {
//         res.status(404).json({ error: "No marks found" });
//       }
//     } catch (error) {
//       console.error("Database error:", error);
//       res.status(500).json({ error: "Failed to retrieve marks" });
//     }
//   });

app.get("/get-assessment-scores", (req, res) => {
    pool.query("SELECT mcq_answer, descriptive_score, total_score FROM assessments1 WHERE id = 2", (err, result) => {
      if (err) throw err;
      res.json(result[0]); // Send the first result
    });
  });
  

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
