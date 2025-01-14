const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors());
app.use(bodyParser.json());

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
