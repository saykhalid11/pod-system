const express = require("express");
const cors    = require("cors");
const sql     = require("mssql");
const path    = require("path");

const app = express();
app.use(express.json());
app.use(cors());

// ── Serve the frontend HTML ──────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ── DB config ─────────────────────────────────────────────────────────────
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port:     1433,
  options: {
    encrypt:                false,
    trustServerCertificate: true,
    enableArithAbort:       true,
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMs: 30000,
  },
};

let pool;
async function getPool() {
  if (!pool) {
    try {
      pool = await sql.connect(dbConfig);
      console.log("✅ Connected to SQL Server");
    } catch (err) {
      pool = null;
      throw err;
    }
  }
  return pool;
}

// ── GET /api/sales-orders ────────────────────────────────────────────────
app.get("/api/sales-orders", async (req, res) => {
  const { from, to, customer } = req.query;
  if (!from || !to)
    return res.status(400).json({ error: "from and to date params are required." });

  try {
    const db   = await getPool();
    const req2 = db.request();
    req2.input("from", sql.Date, from);
    req2.input("to",   sql.Date, to);

    let query = `
      SELECT
        SONo, DocDate, CustomerCode, CustomerName, DeliveryAddress,
        ItemDescription, Qty, Unit, Rate, Gross,
        TaxableAmt, SStAmount, SubTotal
      FROM tbl_SO_Cache
      WHERE DocDate BETWEEN @from AND @to
    `;

    if (customer && customer.trim()) {
      req2.input("customer", sql.NVarChar, `%${customer.trim()}%`);
      query += ` AND CustomerName LIKE @customer`;
    }

    query += ` ORDER BY DocDate DESC, SONo`;

    const result = await req2.query(query);

    // Group rows by SONo → each order gets an items[] array
    const map = {};
    for (const row of result.recordset) {
      if (!map[row.SONo]) {
        map[row.SONo] = {
          id:           row.SONo,
          date:         row.DocDate ? row.DocDate.toISOString().split("T")[0] : "",
          customerCode: row.CustomerCode,
          customer:     row.CustomerName,
          address:      row.DeliveryAddress || "",
          taxableAmt:   parseFloat(row.TaxableAmt)  || 0,
          sstAmount:    parseFloat(row.SStAmount)    || 0,
          subTotal:     parseFloat(row.SubTotal)     || 0,
          items:        [],
        };
      }
      map[row.SONo].items.push({
        name:  row.ItemDescription,
        qty:   parseFloat(row.Qty)   || 0,
        unit:  row.Unit,
        rate:  parseFloat(row.Rate)  || 0,
        gross: parseFloat(row.Gross) || 0,
      });
    }

    return res.json(Object.values(map));
  } catch (err) {
    console.error("DB Error:", err.message);
    return res.status(500).json({ error: "Database query failed.", detail: err.message });
  }
});

// ── POST /api/delivery-status ────────────────────────────────────────────
app.post("/api/delivery-status", async (req, res) => {
  const { salesOrderNo, deliveryStatus, remarks, updatedBy } = req.body;
  if (!salesOrderNo || !deliveryStatus)
    return res.status(400).json({ error: "salesOrderNo and deliveryStatus are required." });

  const valid = ["completed", "pending", "cancelled"];
  if (!valid.includes(deliveryStatus))
    return res.status(400).json({ error: "Invalid deliveryStatus." });

  try {
    const db   = await getPool();
    const req2 = db.request();
    req2.input("SONo",           sql.NVarChar(50),  salesOrderNo);
    req2.input("DeliveryStatus", sql.NVarChar(20),  deliveryStatus);
    req2.input("Remarks",        sql.NVarChar(500), remarks   || "");
    req2.input("UpdatedBy",      sql.NVarChar(100), updatedBy || "POD_USER");
    req2.input("UpdatedAt",      sql.DateTime,      new Date());

    await req2.query(`
      IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_NAME = 'tbl_POD_Log'
      )
      BEGIN
        CREATE TABLE tbl_POD_Log (
          ID             INT IDENTITY(1,1) PRIMARY KEY,
          SONo           NVARCHAR(50)  NOT NULL,
          DeliveryStatus NVARCHAR(20)  NOT NULL,
          Remarks        NVARCHAR(500),
          UpdatedBy      NVARCHAR(100),
          UpdatedAt      DATETIME DEFAULT GETDATE()
        )
      END

      DELETE FROM tbl_POD_Log WHERE SONo = @SONo

      INSERT INTO tbl_POD_Log (SONo, DeliveryStatus, Remarks, UpdatedBy, UpdatedAt)
      VALUES (@SONo, @DeliveryStatus, @Remarks, @UpdatedBy, @UpdatedAt)
    `);

    return res.json({ success: true, message: `POD saved for ${salesOrderNo}` });
  } catch (err) {
    console.error("DB Error:", err.message);
    return res.status(500).json({ error: "Failed to save POD.", detail: err.message });
  }
});

// ── Health check ─────────────────────────────────────────────────────────
app.get("/api/health", (req, res) =>
  res.json({ status: "ok", time: new Date().toISOString() })
);

// ── Catch-all → serve frontend ───────────────────────────────────────────
app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 POD System running on port ${PORT}`));
