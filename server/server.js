const express = require('express');
const cors = require('cors');
const fs = require('fs');
const { exec } = require('child_process');
const path = require('path');
const multer = require('multer');
const { spawn } = require('child_process');
const bodyParser = require('body-parser');
const mongoose = require('./database');
const Protocol = require('./Protocol');
const { ConnectionPoolMonitoringEvent } = require('mongodb');
const { ObjectId } = require('mongodb');

const app = express();
const port = 8383;

// Middleware
app.use(cors());
app.use(express.text());
app.use(express.json());
app.use(bodyParser.json());

const runPythonScript = (args = []) => {
  return new Promise((resolve, reject) => {
      const python = spawn('python3', ['/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/predict_DPI.py', ...args]);
      let output = '';
      let errorOutput = '';
      let isResolved = false;

      python.stdout.on('data', (data) => {
          output += data.toString();
      });

      python.stderr.on('data', (data) => {
          errorOutput += data.toString();
      });

      python.on('close', (code) => {
          console.log(`Python script exited with code ${code}`);
          if (!isResolved) {
              isResolved = true;
              if (code === 0) {
                console.log('Python script output:', output);
                  resolve(output);
              } else {
                  reject(errorOutput || `Process exited with code ${code}`);
              }
          }
      });
  });
};

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Directory where files will be stored
  },
  filename: (req, file, cb) => {
    // Keep the original filename or modify as you see fit
    cb(null, file.originalname);
  },
});

// This will allow multiple files to be uploaded under the same field name "pcapFile"
const upload = multer({ storage: storage });

// Routes
// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the Node.js server!\n');
});

// Upload route for PCAP files (multiple files)
app.post('/upload', upload.array('pcapFile'), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ message: 'No files uploaded' });
  }

  req.files.forEach((file) => {
    console.log(`Received file: ${file.originalname}, saved to: ${file.path}`);
  });

  // You can perform additional processing here if needed

  res.status(200).json({
    message: 'Files uploaded successfully',
    files: req.files,
  });
});

// Route for receiving and processing text data
let serverOutput = 'X';

app.post('/data', async (req, res) => {
  try {
    const allData = (req.body).split(/\r?\n/);
    console.log(allData);
    const Protocolname = allData[0];
    const data = allData.slice(1).join('\n');
    console.log('Received text data:\n', data);

    // Write file using promisified version
    await fs.promises.writeFile('received_data.txt', data);
    console.log('Data saved to received_data.txt');

    // Combine PCAP files
    await new Promise((resolve, reject) => {
      exec('/usr/bin/python3 "/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/combine_pcaps.py"',
        (error, stdout) => {
          if (error) reject(error);
          else {
            console.log('Combined the pcap files:', stdout);
            resolve();
          }
        }
      );
    });

    // Run Python script
    console.log('Running ML Python script');
    const pythonArgs = ['/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/server/runfile.pcapng',Protocolname];
    const result = await runPythonScript(pythonArgs);
    console.log(result);
    console.log('Python ML script finished');

    await new Promise((resolve, reject) => {
      exec('/usr/bin/python3  /mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/gens/generate_dissector.py', (error) => {
        if (error) reject(error);
        else {
          console.log('generated dissector files');
          resolve();
        }
      });
    });

    const dpiData = JSON.parse(fs.readFileSync('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/server/dpi_output.json', 'utf8'));
    serverOutput = dpiData;

    return res.status(200).json({
      success: true,
      message: 'All processing completed successfully',
    });

  } catch (error) {
    console.error('Processing error:', error);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Route to fetch output
app.get('/output', (req, res) => {
   res.send(serverOutput.dpi);
});

// Route to download the dissector file
app.get('/download-dissector', async (req, res) => {
  console.log(req.query);
  console.log('Downloading dissector file');

  // Determine the filename based on query parameters.
  let filename;
  if (!req.query.ip) {
    // No IP provided; assume a request for the static dissector.
    const protocol = req.query.protocol || 'my_protocol_dissector';
    filename = `${protocol}.lua`;
  } else {
    if (req.query.ip === 'Global') {
      const protocol = req.query.protocol;
      filename = `${protocol}.lua`;
    } else {
      let ip = req.query.ip.replace(/\./g, "_");
      const protocol = req.query.protocol;
      // Default to '100%' if no percentage is provided.
      let percentage = req.query.percentage || '100%';
      percentage = percentage.replace('%', 'pct');
      filename = `${protocol}_for_${ip}_${percentage}.lua`;
    }
  }

  // Everything inside the route: Connect to MongoDB, retrieve the document, and send the content.
  const { MongoClient } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  try {
    client = new MongoClient(uri);
    await client.connect();
    const db = client.db('lua_dissectors_db');
    const collection = db.collection('dissectors');

    // Find the document with the specified filename.
    const fileDoc = await collection.findOne({ filename });
    if (!fileDoc) {
      res.status(404).send('File not found in database.');
    } else {
      // Set headers to trigger file download.
      res.set({
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Type': 'text/plain'
      });
      res.send(fileDoc.content);
    }
  } catch (err) {
    console.error('Error retrieving file from database:', err);
    res.status(500).send('Error retrieving file from database.');
  } finally {
    if (client) {
      await client.close();
    }
  }
});

app.post('/save-protocol', async (req, res) => {
  try {
      const { name, fields, files, dpi } = req.body;
    
      // Create a new protocol with the data directly
      const newProtocol = new Protocol({
          name,
          //if the type of the field  start with custom: then replace the "custom:" with ""
          fields: fields.map(field => ({
            ...field,
            type: field.type.startsWith('custom:') ? field.type.replace('custom:', '') : field.type
          })),
          files,
          dpi  // Use the dpi object directly - Mixed type accepts any structure
      });

      await newProtocol.save();

      res.status(201).json({
          message: 'Protocol saved successfully',
          data: newProtocol
      });

  } catch (error) {
      console.error('Error saving protocol:', error);
      res.status(500).json({ 
          message: 'Error saving protocol', 
          error: error.message 
      });
  }
});

app.get('/get-protocols', async (req, res) => {
    try {
        const protocols = await Protocol.find();
        res.status(200).json(protocols);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving protocols', error });
    }
});

app.get('/get-names', async (req, res) => {
    try {
        const protocols = await Protocol.find({}, 'name');
        res.status(200).json(protocols.map(p => p.name));
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving protocol names', error });
    }
});

app.get('/get-protocol', async (req, res) => {
    console.log('get-protocol');
    try {
        let name = req.query.name;
        console.log(name);
       
        const protocol = await Protocol.findOne({
            name
        });
        res.status(200).json(protocol);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving protocol', error });
    }
});

app.delete('/delete-protocol', async (req, res) => {
  console.log('delete-protocol');
    try {
      console.log(req.query);
        const name = req.query.name;
        await Protocol.deleteOne({ name });

        res.status(200).json({ message: 'Protocol deleted successfully ' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting protocol', error });
    }
});

app.get('/test', async (req, res) => {
  console.log(req.query);
  console.log('Downloading dissector file');

  // Determine the filename based on query parameters.
  let filename;
  if (!req.query.ip) {
    // No IP provided; assume a request for the static dissector.
    const protocol = req.query.protocol || 'my_protocol_dissector';
    filename = `${protocol}.lua`;
  } else {
    if (req.query.ip === 'Global') {
      const protocol = req.query.protocol;
      filename = `${protocol}.lua`;
    } else {
      let ip = req.query.ip.replace(/\./g, "_");
      const protocol = req.query.protocol;
      // Default to '100%' if no percentage is provided.
      let percentage = req.query.percentage || '100%';
      percentage = percentage.replace('%', 'pct');
      filename = `${protocol}_for_${ip}_${percentage}.lua`;
    }
  }

  // Everything inside the route: Connect to MongoDB, retrieve the document, and send the content.
  const { MongoClient } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  try {
    client = new MongoClient(uri, { useUnifiedTopology: true });
    await client.connect();
    const db = client.db('lua_dissectors_db');
    const collection = db.collection('dissectors');

    // Find the document with the specified filename.
    const fileDoc = await collection.findOne({ filename });
    if (!fileDoc) {
      res.status(404).send('File not found in database.');
    } else {
      // Set headers to trigger file download.
      res.set({
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Type': 'text/plain'
      });
      res.send(fileDoc.content);
    }
  } catch (err) {
    console.error('Error retrieving file from database:', err);
    res.status(500).send('Error retrieving file from database.');
  } finally {
    if (client) {
      await client.close();
    }
  }
});

/**
 * CUSTOM TYPES API ROUTES
 */

/**
 * GET /custom-types
 * Retrieves all custom types directly from MongoDB
 */
app.get('/custom-types', async (req, res) => {
  const { MongoClient } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  
  try {
    client = new MongoClient(uri);
    await client.connect();
    const db = client.db('custom_types_db');  // Or any other name you prefer // Use your database name
    const collection = db.collection('customtypes');
    
    const customTypes = await collection.find({}).toArray();
    res.json(customTypes);
  } catch (error) {
    console.error('Error retrieving custom types:', error);
    res.status(500).json({ error: 'Failed to retrieve custom types' });
  } finally {
    if (client) {
      await client.close();
    }
  }
});

/**
 * GET /custom-types/:id
 * Retrieves a specific custom type by ID
 */
app.get('/custom-types/:id', async (req, res) => {
  const { MongoClient, ObjectId } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  
  try {
    const { id } = req.params;
    client = new MongoClient(uri);
    await client.connect();
    const db = client.db('custom_types_db');  // Or any other name you prefer// Use your database name
    const collection = db.collection('customtypes');
    
    const customType = await collection.findOne({ _id: new ObjectId(id) });
    
    if (!customType) {
      return res.status(404).json({ error: 'Custom type not found' });
    }
    
    res.json(customType);
  } catch (error) {
    console.error('Error retrieving custom type:', error);
    res.status(500).json({ error: 'Failed to retrieve custom type' });
  } finally {
    if (client) {
      await client.close();
    }
  }
});

/**
 * POST /custom-types
 * Creates a new custom type directly in MongoDB
 */
app.post('/custom-types', async (req, res) => {
  const { MongoClient } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  
  try {
    console.log('Received custom type data:', JSON.stringify(req.body));
    
    const customTypeData = req.body;
    
    // Validate required fields
    if (!customTypeData.name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    if (!Array.isArray(customTypeData.fields)) {
      return res.status(400).json({ error: 'Fields must be an array' });
    }
    
    client = new MongoClient(uri);
    await client.connect();
    const db = client.db('custom_types_db');  // Or any other name you prefer // Use your database name
    const collection = db.collection('customtypes');
    
    // Check if a type with this name already exists
    const existingType = await collection.findOne({ name: customTypeData.name });
    if (existingType) {
      return res.status(400).json({ error: 'A type with this name already exists' });
    }
    
    // Calculate total size
    const totalSize = customTypeData.fields.reduce((total, field) => {
      const size = parseInt(field.size);
      return total + (isNaN(size) ? 0 : size);
    }, 0);
    
    // Prepare the document to insert
    const customType = {
      name: customTypeData.name,
      fields: customTypeData.fields,
      totalSize: totalSize,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    // Insert the document
    const result = await collection.insertOne(customType);
    
    // Return the created document with the generated ID
    res.status(201).json({
      ...customType,
      _id: result.insertedId
    });
  } catch (error) {
    console.error('Error creating custom type:', error);
    res.status(500).json({ error: `Failed to create custom type: ${error.message}` });
  } finally {
    if (client) {
      await client.close();
    }
  }
});

/**
 * PUT /custom-types/:id
 * Updates an existing custom type directly in MongoDB
 */
app.put('/custom-types/:id', async (req, res) => {
  const { MongoClient, ObjectId } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  
  try {
    const { id } = req.params;
    const { name, fields } = req.body;
    
    // Validate required fields
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    if (!Array.isArray(fields)) {
      return res.status(400).json({ error: 'Fields must be an array' });
    }
    
    client = new MongoClient(uri);
    await client.connect();
    const db = client.db('custom_types_db');  // Or any other name you prefer // Use your database name
    const collection = db.collection('customtypes');
    
    // Check if another type with this name already exists
    const existingType = await collection.findOne({
      name: name,
      _id: { $ne: new ObjectId(id) }
    });
    
    if (existingType) {
      return res.status(400).json({ error: 'Another type with this name already exists' });
    }
    
    // Calculate total size
    const totalSize = fields.reduce((total, field) => {
      const size = parseInt(field.size);
      return total + (isNaN(size) ? 0 : size);
    }, 0);
    
    // Update the document
    const result = await collection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      {
        $set: {
          name: name,
          fields: fields,
          totalSize: totalSize,
          updatedAt: new Date()
        }
      },
      { returnDocument: 'after' }
    );
    
    if (!result) {
      return res.status(404).json({ error: 'Custom type not found' });
    }
    
    res.json(result);
  } catch (error) {
    console.error('Error updating custom type:', error);
    res.status(500).json({ error: 'Failed to update custom type' });
  } finally {
    if (client) {
      await client.close();
    }
  }
});

/**
 * DELETE /custom-types/:id
 * Deletes a custom type directly from MongoDB
 */
app.delete('/custom-types/:id', async (req, res) => {
  const { MongoClient, ObjectId } = require('mongodb');
  const uri = 'mongodb://localhost:27017';
  let client;
  
  try {
    const { id } = req.params;
    
    client = new MongoClient(uri);
    await client.connect();
    const db = client.db('custom_types_db');  // Or any other name you prefer // Use your database name
    const collection = db.collection('customtypes');
    
    const result = await collection.deleteOne({ _id: new ObjectId(id) });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Custom type not found' });
    }
    
    res.status(200).json({ message: 'Custom type deleted successfully' });
  } catch (error) {
    console.error('Error deleting custom type:', error);
    res.status(500).json({ error: 'Failed to delete custom type' });
  } finally {
    if (client) {
      await client.close();
    }
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
