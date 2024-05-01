import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from "@google/generative-ai";
import fs from 'fs';
import FormData from 'form-data';
import got from 'got';
import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import cors from 'cors';
import path from 'path';                      // Node.js module for handling and transforming file paths

import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs'
const JWT_SECRET = 'Major_project';          // Keep this secret safe
const app = express();

// Middlewares
app.use(cors()); // Enable CORS for all routes
app.use(express.json());
// Configure storage for multer


// open AI 
const MODEL_NAME = "gemini-1.0-pro";
const API_KEY = "AIzaSyBYorJGIgHjWIWU55Er9-DXRP3aEjF_x08";

// IMAGGA
const imagga_apikey = 'acc_dd4e0ba383cd832';
const imagga_apisecret = '7546f7b4624c0e8e00e409cbfe72e01b';

mongoose.connect('mongodb://127.0.0.1:27017/Major_Project')  
.then(()=>{ 

console.log('connect with monogo db')

})
.catch((error)=>{

console.log(error);

})
  
const UserSignupSchema = new mongoose.Schema({ 
  name: { type: String, required: true }, 
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const UserSignup=mongoose.model('UserSignup', UserSignupSchema);


const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid Token' });
  }
};

app.post('/signin', async (req, res) => {
  const { email, password }= req.body;
  
  try {
    const user = await UserSignup.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token, including the user's name
    const token = jwt.sign(
      { userId: user._id, name: user.name }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );
    res.json({ message: 'Authenticated successfully', token });
  } catch (error) {
    res.status(500).json({ message: 'Authentication failed', error: error.message });
  }
});



//Signup form
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await UserSignup.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new UserSignup({ name, email, password: hashedPassword });
    await newUser.save();

    // Generate token, now including the user's name
    const token = jwt.sign(
      { userId: newUser._id, name: newUser.name }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );
    res.status(201).json({ message: 'User created successfully', token });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});


app.get('/protected', verifyToken, (req, res) => {
  // Access user id from req.user.userId
  res.json({ message: 'Welcome to the protected route!' });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'), // Set destination to 'uploads/' folder
  filename: (req, file, cb) => {
    // Create a new filename with the original name and .png extension
    const ext = path.extname(file.originalname).toLowerCase();
    const baseName = path.basename(file.originalname, ext);
    const newName = baseName + '-' + Date.now() + '.png';

    cb(null, newName);
  }
});


const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    // Accept images only
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  }
});

// Routes



// open AI AND IMAGGA FUnction ------------------------



async function run(userInput) {
  
  const genAI = new GoogleGenerativeAI(API_KEY);
  const model = genAI.getGenerativeModel({ model: MODEL_NAME });

  const generationConfig = {
    temperature: 0.9,
    topK: 1,
    topP: 1,
    maxOutputTokens: 2048,
  };

  const safetySettings = [
    { 
      category: HarmCategory.HARM_CATEGORY_HARASSMENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
  ];

  const parts = [
    {
      text: `
      I'm looking for detailed information about: ${userInput}. Please provide the following:
     
      1. A complete description of ${userInput}, including its appearance, taste (if applicable), and any unique characteristics or historical significance.
      2. If ${userInput} is related to food or nutrition, provide detailed nutritional information, such as calorie content, carbohydrates, dietary fiber, vitamin C, potassium, and any other relevant nutritional facts.
      3. A list of types or varieties that exist worldwide, highlighting both common and exotic types if ${userInput} has such variations.
      4. Links to reputable websites where ${userInput} can be purchased online or where further reputable information about ${userInput} can be found. Please provide only the homepage clickable link of each website.
      
      Please provide comprehensive and accurate information, ensuring the response is well-structured and informative.`
    } 
  
  ];

  const result = await model.generateContent({
    contents: [{ role: "user", parts }],
    generationConfig,
    safetySettings,
  }); 

  const response = result.response;
  console.log(response.text());
  return response.text();
}



async function analyzeImageWithImagga(imagepath, imagga_apikey, imagga_apisecret) {
  
  const form = new FormData();
  form.append('image', fs.createReadStream(imagepath));

  try {
      const response = await got.post('https://api.imagga.com/v2/tags', {
          body: form,
          headers: {
              'Authorization': `Basic ${Buffer.from(`${ imagga_apikey}:${imagga_apisecret}`).toString('base64')}`
          },
          responseType: 'json'
      });

      console.log(response.body);
      return response.body;
  } catch (error) {
      console.error('Error analyzing image with Imagga:', error.response?.body || error.message);
      throw error; // Rethrow the error for upstream handling
  }
}
  





app.post('/upload', upload.single('image'), async (req, res) => {
  
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }

 let imagepath=req.file.path;
console.log(req.file.path);
 
let finalanswer= await analyzeImageWithImagga(imagepath,imagga_apikey,imagga_apisecret)

console.log(finalanswer.result.tags[0].tag.en);

 let resdata= await run(finalanswer.result.tags[0].tag.en);

res.send(resdata);

});



app.post('/analyze-text', async (req, res) => {
  const { text } = req.body;

  
  if (!text) {
    return res.status(400).send('No text provided.');
  }

  try {
    // Use the OpenAI function to process the text
    const response = await run(text);
    res.send(response);
  } catch (error) {
    console.error('Error processing text:', error);
    res.status(500).send('Error processing text');
  }
});

// Start server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
