require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 8080;

if (!process.env.SESSION_SECRET) {
    console.error('❌ SESSION_SECRET manquant dans .env');
    process.exit(1);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 30000,
    enableKeepAlive: true
});

async function checkConnection() {
    try {
        const conn = await pool.getConnection();
        await conn.query('SELECT 1');
        conn.release();
        console.log('✅ Connexion MySQL établie');
    } catch (err) {
        console.error('❌ Erreur MySQL:', err.message);
        setTimeout(checkConnection, 5000);
    }
}
checkConnection();

function requireAuth(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
    req.userId = req.session.userId;
    next();
}

async function getStationId(userId) {
    const [rows] = await pool.query('SELECT station_id FROM users WHERE id = ?', [userId]);
    return rows[0]?.station_id;
}

// --- Route pour les capteurs (sans authentification, ou avec clé API si besoin) ---
// Ici on suppose que les capteurs sont physiquement sécurisés, on ajoute une vérification simple par clé
// Pour simplifier, on accepte sans auth mais on vérifie que la pompe appartient à une station existante.
app.post('/api/sensor/:pump_id', async (req, res) => {
    const pump_id = parseInt(req.params.pump_id);
    const { liters, api_key } = req.body; // liters = volume écoulé depuis dernier relevé (incrément)
    if (!liters || liters <= 0) return res.status(400).json({ error: 'Litres invalides' });
    // Optionnel : vérifier api_key (à définir dans .env)
    if (process.env.SENSOR_API_KEY && api_key !== process.env.SENSOR_API_KEY) {
        return res.status(403).json({ error: 'Clé API invalide' });
    }
    try {
        // Vérifier que la pompe existe
        const [pump] = await pool.query('SELECT id FROM pumps WHERE id = ?', [pump_id]);
        if (pump.length === 0) return res.status(404).json({ error: 'Pompe inconnue' });
        await pool.query('INSERT INTO fuel_readings (pump_id, liters, timestamp) VALUES (?, ?, NOW())', [pump_id, liters]);
        res.json({ success: true, pump_id, liters });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// --- Routes d'authentification (inchangées) ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Champs requis' });
    try {
        const [rows] = await pool.query('SELECT id, password_hash FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ error: 'Identifiants invalides' });
        const match = await bcrypt.compare(password, rows[0].password_hash);
        if (!match) return res.status(401).json({ error: 'Identifiants invalides' });
        req.session.userId = rows[0].id;
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/check_auth', (req, res) => {
    res.json({ authenticated: !!req.session.userId });
});
app.get('/api/station_info', requireAuth, async (req, res) => {
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        const [rows] = await pool.query('SELECT name, logo_url FROM stations WHERE id = ?', [stationId]);
        if (rows.length === 0) return res.status(404).json({ error: 'Station non trouvée' });
        res.json({ name: rows[0].name, logo_url: rows[0].logo_url });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/pumps', requireAuth, async (req, res) => {
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        const [rows] = await pool.query('SELECT id, pump_number, fuel_type FROM pumps WHERE station_id = ? ORDER BY pump_number', [stationId]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- NOUVELLE ROUTE : statistiques par pompe sur une période ---
app.get('/api/stats/pumps', requireAuth, async (req, res) => {
    const { start, end } = req.query;
    if (!start || !end) return res.status(400).json({ error: 'start et end requis' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        const query = `
            SELECT p.id, p.pump_number, p.fuel_type, 
                   COALESCE(SUM(fr.liters), 0) as total_liters
            FROM pumps p
            LEFT JOIN fuel_readings fr ON fr.pump_id = p.id 
                AND fr.timestamp BETWEEN ? AND ?
            WHERE p.station_id = ?
            GROUP BY p.id, p.pump_number, p.fuel_type
            ORDER BY p.pump_number
        `;
        const [rows] = await pool.query(query, [start, end + ' 23:59:59', stationId]);
        const prices = { diesel: 600, gasoline: 650 };
        const result = rows.map(r => ({
            pump_number: r.pump_number,
            fuel_type: r.fuel_type,
            liters: parseFloat(r.total_liters),
            amount: parseFloat(r.total_liters) * prices[r.fuel_type]
        }));
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// --- Statistiques quotidiennes (inchangées) ---
app.get('/api/stats/daily', requireAuth, async (req, res) => {
    const { start, end, pump_id } = req.query;
    if (!start || !end) return res.status(400).json({ error: 'start et end requis' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        let query = `
            SELECT DATE(fr.timestamp) as date, p.fuel_type, SUM(fr.liters) as total_liters
            FROM fuel_readings fr
            JOIN pumps p ON fr.pump_id = p.id
            WHERE p.station_id = ? AND fr.timestamp BETWEEN ? AND ?
        `;
        const params = [stationId, start, end + ' 23:59:59'];
        if (pump_id) {
            query += ' AND fr.pump_id = ?';
            params.push(pump_id);
        }
        query += ' GROUP BY DATE(fr.timestamp), p.fuel_type ORDER BY date';
        const [rows] = await pool.query(query, params);
        const dates = [...new Set(rows.map(r => r.date))].sort();
        const dieselData = dates.map(date => {
            const row = rows.find(r => r.date === date && r.fuel_type === 'diesel');
            return row ? parseFloat(row.total_liters) : 0;
        });
        const gasolineData = dates.map(date => {
            const row = rows.find(r => r.date === date && r.fuel_type === 'gasoline');
            return row ? parseFloat(row.total_liters) : 0;
        });
        res.json({ dates, diesel: dieselData, gasoline: gasolineData });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// --- Statistiques hebdomadaires ---
app.get('/api/stats/weekly', requireAuth, async (req, res) => {
    const { year, pump_id } = req.query;
    if (!year) return res.status(400).json({ error: 'year requis' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        let query = `
            SELECT WEEK(fr.timestamp, 3) as week, p.fuel_type, SUM(fr.liters) as total_liters
            FROM fuel_readings fr
            JOIN pumps p ON fr.pump_id = p.id
            WHERE p.station_id = ? AND YEAR(fr.timestamp) = ?
        `;
        const params = [stationId, year];
        if (pump_id) {
            query += ' AND fr.pump_id = ?';
            params.push(pump_id);
        }
        query += ' GROUP BY WEEK(fr.timestamp, 3), p.fuel_type ORDER BY week';
        const [rows] = await pool.query(query, params);
        const weeks = [...new Set(rows.map(r => r.week))].sort();
        const dieselWeekly = weeks.map(week => {
            const row = rows.find(r => r.week === week && r.fuel_type === 'diesel');
            return row ? parseFloat(row.total_liters) : 0;
        });
        const gasolineWeekly = weeks.map(week => {
            const row = rows.find(r => r.week === week && r.fuel_type === 'gasoline');
            return row ? parseFloat(row.total_liters) : 0;
        });
        res.json({ weeks, diesel: dieselWeekly, gasoline: gasolineWeekly });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Statistiques mensuelles (global station) ---
app.get('/api/stats/monthly', requireAuth, async (req, res) => {
    const { year, month, pump_id } = req.query;
    if (!year || !month) return res.status(400).json({ error: 'year et month requis' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404). json({ error: 'Station non trouvée' });
    const startDate = `${year}-${month}-01`;
    const endDate = `${year}-${month}-${new Date(year, month, 0).getDate()} 23:59:59`;
    try {
        let query = `
            SELECT p.fuel_type, SUM(fr.liters) as total_liters
            FROM fuel_readings fr
            JOIN pumps p ON fr.pump_id = p.id
            WHERE p.station_id = ? AND fr.timestamp BETWEEN ? AND ?
        `;
        const params = [stationId, startDate, endDate];
        if (pump_id) {
            query += ' AND fr.pump_id = ?';
            params.push(pump_id);
        }
        query += ' GROUP BY p.fuel_type';
        const [rows] = await pool.query(query, params);
        const dieselLiters = rows.find(r => r.fuel_type === 'diesel')?.total_liters || 0;
        const gasolineLiters = rows.find(r => r.fuel_type === 'gasoline')?.total_liters || 0;
        const DIESEL_PRICE = 600;
        const GASOLINE_PRICE = 650;
        const costDiesel = dieselLiters * DIESEL_PRICE;
        const costGasoline = gasolineLiters * GASOLINE_PRICE;
        res.json({
            diesel_liters: parseFloat(dieselLiters),
            gasoline_liters: parseFloat(gasolineLiters),
            cost_diesel: Math.round(costDiesel),
            cost_gasoline: Math.round(costGasoline),
            total_fcfa: Math.round(costDiesel + costGasoline)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Comparaison mensuelle ---
app.get('/api/stats/monthly_comparison', requireAuth, async (req, res) => {
    const { year, month, pump_id } = req.query;
    if (!year || !month) return res.status(400).json({ error: 'year et month requis' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    async function getMonthlyTotal(year, month, pump_id) {
        const start = `${year}-${month}-01`;
        const end = `${year}-${month}-${new Date(year, month, 0).getDate()} 23:59:59`;
        let query = `
            SELECT SUM(fr.liters) as total_liters
            FROM fuel_readings fr
            JOIN pumps p ON fr.pump_id = p.id
            WHERE p.station_id = ? AND fr.timestamp BETWEEN ? AND ?
        `;
        const params = [stationId, start, end];
        if (pump_id) {
            query += ' AND fr.pump_id = ?';
            params.push(pump_id);
        }
        const [rows] = await pool.query(query, params);
        return parseFloat(rows[0].total_liters) || 0;
    }
    try {
        const currentTotal = await getMonthlyTotal(year, month, pump_id);
        let prevYear = year;
        let prevMonth = parseInt(month) - 1;
        if (prevMonth === 0) {
            prevMonth = 12;
            prevYear = parseInt(year) - 1;
        }
        const previousTotal = await getMonthlyTotal(prevYear, String(prevMonth).padStart(2,'0'), pump_id);
        res.json({
            current: currentTotal,
            previous: previousTotal,
            variation: currentTotal - previousTotal,
            variation_percent: previousTotal === 0 ? 0 : ((currentTotal - previousTotal) / previousTotal * 100)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Moyennes et max ---
app.get('/api/stats/average_max', requireAuth, async (req, res) => {
    const { start, end, pump_id } = req.query;
    if (!start || !end) return res.status(400).json({ error: 'start et end requis' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        let query = `
            SELECT DATE(fr.timestamp) as date, SUM(fr.liters) as daily_liters
            FROM fuel_readings fr
            JOIN pumps p ON fr.pump_id = p.id
            WHERE p.station_id = ? AND fr.timestamp BETWEEN ? AND ?
        `;
        const params = [stationId, start, end + ' 23:59:59'];
        if (pump_id) {
            query += ' AND fr.pump_id = ?';
            params.push(pump_id);
        }
        query += ' GROUP BY DATE(fr.timestamp)';
        const [rows] = await pool.query(query, params);
        const dailyTotals = rows.map(r => parseFloat(r.daily_liters));
        const avg = dailyTotals.length ? dailyTotals.reduce((a,b) => a+b,0)/dailyTotals.length : 0;
        const max = dailyTotals.length ? Math.max(...dailyTotals) : 0;
        res.json({ avg_liters_per_day: parseFloat(avg.toFixed(2)), max_liters_per_day: parseFloat(max.toFixed(2)) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Seuils (inchangés) ---
app.get('/api/thresholds', requireAuth, async (req, res) => {
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        const [rows] = await pool.query('SELECT diesel_threshold, gasoline_threshold FROM thresholds WHERE station_id = ? ORDER BY id DESC LIMIT 1', [stationId]);
        res.json(rows[0] || { diesel_threshold: 1000, gasoline_threshold: 1000 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/thresholds', requireAuth, async (req, res) => {
    const { diesel_threshold, gasoline_threshold } = req.body;
    if (diesel_threshold === undefined || gasoline_threshold === undefined) return res.status(400).json({ error: 'Champs manquants' });
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        await pool.query('INSERT INTO thresholds (station_id, diesel_threshold, gasoline_threshold) VALUES (?, ?, ?)', [stationId, diesel_threshold, gasoline_threshold]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', db: 'connected' });
    } catch (err) {
        res.status(500).json({ status: 'error', db: err.message });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/api/station_info', requireAuth, async (req, res) => {
    const stationId = await getStationId(req.userId);
    if (!stationId) return res.status(404).json({ error: 'Station non trouvée' });
    try {
        const [rows] = await pool.query('SELECT name, location, logo_url FROM stations WHERE id = ?', [stationId]);
        if (rows.length === 0) return res.status(404).json({ error: 'Station introuvable' });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`✅ Serveur carburant démarré sur http://0.0.0.0:${port}`);
});