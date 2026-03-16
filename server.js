const express = require("express");
const cors    = require("cors");
const sql     = require("mssql");
const path    = require("path");
const jwt     = require("jsonwebtoken");
const bcrypt  = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET  = process.env.JWT_SECRET  || "pod_jwt_secret_change_in_production";
const JWT_EXPIRES = "8h";

// ── DB Config ──────────────────────────────────────────────────────────────
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port:     1433,
  options: { encrypt: false, trustServerCertificate: true, enableArithAbort: true },
};

let pool;
async function getPool() {
  if (!pool) {
    try { pool = await sql.connect(dbConfig); console.log("✅ DB Connected"); }
    catch (err) { pool = null; throw err; }
  }
  return pool;
}

// ── Ensure tbl_POD_Users exists ────────────────────────────────────────────
async function ensureUsersTable() {
  try {
    const db = await getPool();
    await db.request().query(`
      IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='tbl_POD_Users')
      BEGIN
        CREATE TABLE tbl_POD_Users (
          ID            INT IDENTITY(1,1) PRIMARY KEY,
          Username      NVARCHAR(100) NOT NULL UNIQUE,
          FullName      NVARCHAR(200) NOT NULL,
          PasswordHash  NVARCHAR(500) NOT NULL,
          IsAdmin       BIT DEFAULT 0,
          IsSuperAdmin  BIT DEFAULT 0,
          CanSubmit     BIT DEFAULT 1,
          CanEditAfterSet BIT DEFAULT 0,
          CanViewReports  BIT DEFAULT 1,
          CanManageUsers  BIT DEFAULT 0,
          IsActive      BIT DEFAULT 1,
          CreatedAt     DATETIME DEFAULT GETDATE()
        )
      END
    `);

    // Create default super admin if no users exist
    const check = await db.request().query(`SELECT COUNT(*) AS cnt FROM tbl_POD_Users`);
    if (check.recordset[0].cnt === 0) {
      const hash = await bcrypt.hash("Admin@123", 10);
      await db.request()
        .input("u",  sql.NVarChar(100), "admin")
        .input("fn", sql.NVarChar(200), "Super Admin")
        .input("ph", sql.NVarChar(500), hash)
        .query(`
          INSERT INTO tbl_POD_Users
            (Username,FullName,PasswordHash,IsAdmin,IsSuperAdmin,CanSubmit,CanEditAfterSet,CanViewReports,CanManageUsers,IsActive)
          VALUES (@u,@fn,@ph,1,1,1,1,1,1,1)
        `);
      console.log("✅ Default super admin created: admin / Admin@123");
    }
  } catch (err) {
    console.error("Users table setup error:", err.message);
  }
}

// ── Auth Middleware ────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "No token provided." });
  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token. Please log in again." });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.canManageUsers) return res.status(403).json({ error: "Admin access required." });
  next();
}

// ══════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required." });
  try {
    const db  = await getPool();
    const req2 = db.request().input("u", sql.NVarChar(100), username.trim().toLowerCase());
    const result = await req2.query(`
      SELECT * FROM tbl_POD_Users
      WHERE LOWER(Username) = @u AND IsActive = 1
    `);
    if (!result.recordset.length) return res.status(401).json({ error: "Invalid username or password." });
    const user = result.recordset[0];
    const valid = await bcrypt.compare(password, user.PasswordHash);
    if (!valid) return res.status(401).json({ error: "Invalid username or password." });

    const payload = {
      id:             user.ID,
      username:       user.Username,
      fullName:       user.FullName,
      isAdmin:        !!user.IsAdmin,
      isSuperAdmin:   !!user.IsSuperAdmin,
      canSubmit:      !!user.CanSubmit,
      canEditAfterSet:!!user.CanEditAfterSet,
      canViewReports: !!user.CanViewReports,
      canManageUsers: !!user.CanManageUsers,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    return res.json({ token, user: payload });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: "Login failed.", detail: err.message });
  }
});

// POST /api/auth/change-password
app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: "Both passwords required." });
  if (newPassword.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters." });
  try {
    const db     = await getPool();
    const result = await db.request().input("id", sql.Int, req.user.id)
      .query(`SELECT PasswordHash FROM tbl_POD_Users WHERE ID=@id`);
    const valid = await bcrypt.compare(oldPassword, result.recordset[0].PasswordHash);
    if (!valid) return res.status(400).json({ error: "Old password is incorrect." });
    const hash = await bcrypt.hash(newPassword, 10);
    await db.request().input("id", sql.Int, req.user.id).input("h", sql.NVarChar(500), hash)
      .query(`UPDATE tbl_POD_Users SET PasswordHash=@h WHERE ID=@id`);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Failed to change password.", detail: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// USER MANAGEMENT ROUTES
// ══════════════════════════════════════════════════════════════════════════

// GET /api/users
app.get("/api/users", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const db = await getPool();
    const result = await db.request().query(`
      SELECT ID,Username,FullName,IsAdmin,IsSuperAdmin,CanSubmit,CanEditAfterSet,
             CanViewReports,CanManageUsers,IsActive,CreatedAt
      FROM tbl_POD_Users ORDER BY CreatedAt DESC
    `);
    return res.json(result.recordset);
  } catch (err) {
    return res.status(500).json({ error: "Failed to load users.", detail: err.message });
  }
});

// POST /api/users — create user
app.post("/api/users", authMiddleware, requireAdmin, async (req, res) => {
  const { username, fullName, password, canSubmit, canEditAfterSet, canViewReports, canManageUsers } = req.body;
  if (!username || !fullName || !password) return res.status(400).json({ error: "Username, full name and password required." });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });
  try {
    const hash = await bcrypt.hash(password, 10);
    const db   = await getPool();
    await db.request()
      .input("u",   sql.NVarChar(100), username.trim().toLowerCase())
      .input("fn",  sql.NVarChar(200), fullName.trim())
      .input("ph",  sql.NVarChar(500), hash)
      .input("cs",  sql.Bit, canSubmit      ? 1 : 0)
      .input("cea", sql.Bit, canEditAfterSet? 1 : 0)
      .input("cvr", sql.Bit, canViewReports ? 1 : 0)
      .input("cmu", sql.Bit, canManageUsers ? 1 : 0)
      .query(`
        INSERT INTO tbl_POD_Users
          (Username,FullName,PasswordHash,CanSubmit,CanEditAfterSet,CanViewReports,CanManageUsers,IsActive)
        VALUES (@u,@fn,@ph,@cs,@cea,@cvr,@cmu,1)
      `);
    return res.json({ success: true });
  } catch (err) {
    if (err.message.includes("UNIQUE") || err.message.includes("unique")) return res.status(400).json({ error: "Username already exists." });
    return res.status(500).json({ error: "Failed to create user.", detail: err.message });
  }
});

// PUT /api/users/:id — update user
app.put("/api/users/:id", authMiddleware, requireAdmin, async (req, res) => {
  const { fullName, canSubmit, canEditAfterSet, canViewReports, canManageUsers, isActive, newPassword } = req.body;
  const userId = parseInt(req.params.id);
  try {
    const db = await getPool();
    // Prevent deactivating super admin
    const check = await db.request().input("id", sql.Int, userId)
      .query(`SELECT IsSuperAdmin FROM tbl_POD_Users WHERE ID=@id`);
    if (check.recordset[0]?.IsSuperAdmin && isActive === false)
      return res.status(400).json({ error: "Cannot deactivate super admin." });

    const req2 = db.request()
      .input("id",  sql.Int,          userId)
      .input("fn",  sql.NVarChar(200), fullName)
      .input("cs",  sql.Bit, canSubmit      ? 1 : 0)
      .input("cea", sql.Bit, canEditAfterSet? 1 : 0)
      .input("cvr", sql.Bit, canViewReports ? 1 : 0)
      .input("cmu", sql.Bit, canManageUsers ? 1 : 0)
      .input("ia",  sql.Bit, isActive       ? 1 : 0);

    let query = `
      UPDATE tbl_POD_Users
      SET FullName=@fn, CanSubmit=@cs, CanEditAfterSet=@cea,
          CanViewReports=@cvr, CanManageUsers=@cmu, IsActive=@ia
    `;
    if (newPassword && newPassword.length >= 6) {
      const hash = await bcrypt.hash(newPassword, 10);
      req2.input("ph", sql.NVarChar(500), hash);
      query += `, PasswordHash=@ph`;
    }
    query += ` WHERE ID=@id`;
    await req2.query(query);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Failed to update user.", detail: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// SALES ORDERS
// ══════════════════════════════════════════════════════════════════════════

// GET /api/sales-orders
app.get("/api/sales-orders", authMiddleware, async (req, res) => {
  const { from, to, customer } = req.query;
  if (!from || !to) return res.status(400).json({ error: "from and to dates required." });
  try {
    const db   = await getPool();
    const req2 = db.request().input("from", sql.Date, from).input("to", sql.Date, to);
    let where  = "WHERE DocDate BETWEEN @from AND @to";
    if (customer && customer.trim()) {
      req2.input("cust", sql.NVarChar, `%${customer.trim()}%`);
      where += " AND CustomerName LIKE @cust";
    }
    const result = await req2.query(`
      SELECT
        SONo, DocDate, CustomerCode, CustomerName, DeliveryAddress,
        ItemDescription, Qty, Unit, Rate, Gross, TaxableAmt, SStAmount, SubTotal,
        (SELECT hd.DOStatus FROM tCore_Header_0 h
          JOIN tCore_HeaderData5634_0 hd ON h.iHeaderId=hd.iHeaderId
          WHERE h.iVoucherType=5634 AND h.sVoucherNo=SONo) AS DOStatus,
        (SELECT hd.CancellationRemarks FROM tCore_Header_0 h
          JOIN tCore_HeaderData5634_0 hd ON h.iHeaderId=hd.iHeaderId
          WHERE h.iVoucherType=5634 AND h.sVoucherNo=SONo) AS CancellationRemarks
      FROM tbl_SO_Cache ${where}
      ORDER BY DocDate DESC, SONo
    `);

    const map = {};
    for (const row of result.recordset) {
      if (!map[row.SONo]) {
        map[row.SONo] = {
          id:                  row.SONo,
          date:                row.DocDate ? row.DocDate.toISOString().split("T")[0] : "",
          customerCode:        row.CustomerCode,
          customer:            row.CustomerName,
          address:             row.DeliveryAddress || "",
          doStatus:            row.DOStatus ?? 0,
          cancellationRemarks: row.CancellationRemarks || "",
          // These 3 columns repeat per item row — must be SUMMED across all rows
          taxableAmt:          0,
          sstAmount:           0,
          subTotal:            0,
          items:               [],
        };
      }
      // Sum per-item values
      map[row.SONo].taxableAmt += parseFloat(row.TaxableAmt) || 0;
      map[row.SONo].sstAmount  += parseFloat(row.SStAmount)  || 0;
      map[row.SONo].subTotal   += parseFloat(row.SubTotal)   || 0;
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
    console.error(err.message);
    return res.status(500).json({ error: "Database query failed.", detail: err.message });
  }
});

// POST /api/sales-orders/status
app.post("/api/sales-orders/status", authMiddleware, async (req, res) => {
  const { salesOrderNo, status, remarks, isEdit } = req.body;
  if (!salesOrderNo || status === undefined) return res.status(400).json({ error: "salesOrderNo and status required." });
  if (![1, 2].includes(parseInt(status))) return res.status(400).json({ error: "Invalid status. Must be 1 (Completed) or 2 (Cancelled)." });
  if (parseInt(status) === 2 && (!remarks || !remarks.trim())) return res.status(400).json({ error: "Remarks are mandatory for cancellation." });
  if (isEdit && !req.user.canEditAfterSet) return res.status(403).json({ error: "You don't have permission to edit after status is set." });
  if (!req.user.canSubmit) return res.status(403).json({ error: "You don't have permission to submit status." });

  try {
    const db   = await getPool();
    const req2 = db.request()
      .input("status",  sql.Int,          parseInt(status))
      .input("remarks", sql.NVarChar(500), remarks || "NA")
      .input("soNo",    sql.NVarChar(100), salesOrderNo);
    await req2.query(`
      UPDATE hd
      SET DOStatus = @status, CancellationRemarks = @remarks
      FROM tCore_HeaderData5634_0 hd
      INNER JOIN tCore_Header_0 h ON h.iHeaderId = hd.iHeaderId
      WHERE h.iVoucherType = 5634 AND h.sVoucherNo = @soNo
    `);
    return res.json({ success: true, message: `SO ${salesOrderNo} updated.` });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: "Failed to update SO status.", detail: err.message });
  }
});

// POST /api/sales-orders/bulk-complete
app.post("/api/sales-orders/bulk-complete", authMiddleware, async (req, res) => {
  const { salesOrderNos } = req.body;
  if (!salesOrderNos?.length) return res.status(400).json({ error: "No orders provided." });
  if (!req.user.canSubmit) return res.status(403).json({ error: "No permission to submit status." });

  try {
    const db = await getPool();
    const results = { success: [], failed: [] };
    for (const soNo of salesOrderNos) {
      try {
        await db.request()
          .input("soNo", sql.NVarChar(100), soNo)
          .query(`
            UPDATE hd SET DOStatus=1, CancellationRemarks='NA'
            FROM tCore_HeaderData5634_0 hd
            INNER JOIN tCore_Header_0 h ON h.iHeaderId=hd.iHeaderId
            WHERE h.iVoucherType=5634 AND h.sVoucherNo=@soNo
          `);
        results.success.push(soNo);
      } catch { results.failed.push(soNo); }
    }
    return res.json(results);
  } catch (err) {
    return res.status(500).json({ error: "Bulk update failed.", detail: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// INVOICES
// ══════════════════════════════════════════════════════════════════════════

// GET /api/invoices
app.get("/api/invoices", authMiddleware, async (req, res) => {
  const { from, to, customer } = req.query;
  if (!from || !to) return res.status(400).json({ error: "from and to dates required." });
  try {
    const db   = await getPool();
    const req2 = db.request().input("from", sql.Date, from).input("to", sql.Date, to);
    let where  = "WHERE InvDate BETWEEN @from AND @to";
    if (customer && customer.trim()) {
      req2.input("cust", sql.NVarChar, `%${customer.trim()}%`);
      where += " AND CustomerName LIKE @cust";
    }
    const result = await req2.query(`
      SELECT
        InvNo, InvDate, CustomerCode, CustomerName, BillingAddress,
        ItemDescription, QTY, UnitCode AS Unit, mRate AS Rate, mGross AS Gross,
        TaxableAmt, SST_Amt AS SSTAmount, Sub_Total AS SubTotal,
        (SELECT hd.InvoiceStatus FROM tCore_Header_0 h
          JOIN tCore_HeaderData3332_0 hd ON h.iHeaderId=hd.iHeaderId
          WHERE h.iVoucherType=3332 AND h.sVoucherNo=InvNo) AS InvoiceStatus,
        (SELECT hd.CancellationRemarks FROM tCore_Header_0 h
          JOIN tCore_HeaderData3332_0 hd ON h.iHeaderId=hd.iHeaderId
          WHERE h.iVoucherType=3332 AND h.sVoucherNo=InvNo) AS CancellationRemarks
      FROM vw_TodaysSalesInvoiceDetails ${where}
      ORDER BY InvDate DESC, InvNo
    `);

    const map = {};
    for (const row of result.recordset) {
      if (!map[row.InvNo]) {
        map[row.InvNo] = {
          id:                  row.InvNo,
          date:                row.InvDate ? row.InvDate.toISOString().split("T")[0] : "",
          customerCode:        row.CustomerCode,
          customer:            row.CustomerName,
          address:             row.BillingAddress || "",
          invoiceStatus:       row.InvoiceStatus ?? 0,
          cancellationRemarks: row.CancellationRemarks || "",
          // These 3 columns repeat per item row — must be SUMMED across all rows
          taxableAmt:          0,
          sstAmount:           0,
          subTotal:            0,
          items:               [],
        };
      }
      // Sum per-item values
      map[row.InvNo].taxableAmt += parseFloat(row.TaxableAmt) || 0;
      map[row.InvNo].sstAmount  += parseFloat(row.SSTAmount)  || 0;
      map[row.InvNo].subTotal   += parseFloat(row.SubTotal)   || 0;
      map[row.InvNo].items.push({
        name:  row.ItemDescription,
        qty:   parseFloat(row.QTY)  || 0,
        unit:  row.Unit,
        rate:  parseFloat(row.Rate) || 0,
        gross: parseFloat(row.Gross)|| 0,
      });
    }
    return res.json(Object.values(map));
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: "Database query failed.", detail: err.message });
  }
});

// POST /api/invoices/status
app.post("/api/invoices/status", authMiddleware, async (req, res) => {
  const { invoiceNo, status, remarks, isEdit } = req.body;
  if (!invoiceNo || status === undefined) return res.status(400).json({ error: "invoiceNo and status required." });
  if (parseInt(status) !== 2) return res.status(400).json({ error: "Only Cancelled (2) is allowed for invoice update." });
  if (!remarks || !remarks.trim()) return res.status(400).json({ error: "Remarks are mandatory for cancellation." });
  if (isEdit && !req.user.canEditAfterSet) return res.status(403).json({ error: "You don't have permission to edit after status is set." });
  if (!req.user.canSubmit) return res.status(403).json({ error: "No permission to submit status." });

  try {
    const db = await getPool();
    await db.request()
      .input("status",  sql.Int,          parseInt(status))
      .input("remarks", sql.NVarChar(500), remarks.trim())
      .input("invNo",   sql.NVarChar(100), invoiceNo)
      .query(`
        UPDATE hd
        SET InvoiceStatus = @status, CancellationRemarks = @remarks
        FROM tCore_HeaderData3332_0 hd
        INNER JOIN tCore_Header_0 h ON h.iHeaderId = hd.iHeaderId
        WHERE h.iVoucherType = 3332 AND h.sVoucherNo = @invNo
      `);
    return res.json({ success: true, message: `Invoice ${invoiceNo} cancelled.` });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: "Failed to update invoice status.", detail: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// KPI ENDPOINTS (independent — no order load needed)
// Uses efficient single-JOIN approach instead of correlated subqueries
// ══════════════════════════════════════════════════════════════════════════

// GET /api/kpi/so?from=&to=
app.get("/api/kpi/so", authMiddleware, async (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error: "from and to required." });
  try {
    const db     = await getPool();
    const result = await db.request()
      .input("from", sql.Date, from)
      .input("to",   sql.Date, to)
      .query(`
        -- Step 1: Get one row per SONo with its summed SubTotal and status
        -- Join cache with header data ONCE using a CTE for efficiency
        WITH SO_Summary AS (
          SELECT
            s.SONo,
            SUM(s.SubTotal)      AS SubTotalSum,
            MAX(hd.DOStatus)     AS DOStatus
          FROM tbl_SO_Cache s
          LEFT JOIN tCore_Header_0 h
            ON h.sVoucherNo = s.SONo AND h.iVoucherType = 5634
          LEFT JOIN tCore_HeaderData5634_0 hd
            ON hd.iHeaderId = h.iHeaderId
          WHERE s.DocDate BETWEEN @from AND @to
          GROUP BY s.SONo
        )
        SELECT
          COUNT(*)                                              AS TotalCount,
          SUM(SubTotalSum)                                      AS TotalValue,
          SUM(CASE WHEN DOStatus = 1 THEN 1 ELSE 0 END)        AS CompletedCount,
          SUM(CASE WHEN DOStatus = 2 THEN 1 ELSE 0 END)        AS CancelledCount,
          SUM(CASE WHEN DOStatus = 1 THEN SubTotalSum ELSE 0 END) AS CompletedValue,
          SUM(CASE WHEN DOStatus = 2 THEN SubTotalSum ELSE 0 END) AS CancelledValue
        FROM SO_Summary
      `);
    const r         = result.recordset[0];
    const total     = r.TotalCount     || 0;
    const completed = r.CompletedCount || 0;
    const cancelled = r.CancelledCount || 0;
    const pending   = total - completed - cancelled;
    const totalVal  = parseFloat(r.TotalValue)     || 0;
    const compVal   = parseFloat(r.CompletedValue) || 0;
    const cancVal   = parseFloat(r.CancelledValue) || 0;
    return res.json({
      totalCount:       total,
      completedCount:   completed,
      cancelledCount:   cancelled,
      pendingCount:     pending,
      totalValue:       totalVal,
      completedValue:   compVal,
      cancelledValue:   cancVal,
      pendingValue:     totalVal - compVal - cancVal,
      completionRate:   total > 0 ? (completed / total * 100).toFixed(1) : "0.0",
      cancellationRate: total > 0 ? (cancelled / total * 100).toFixed(1) : "0.0",
    });
  } catch (err) {
    console.error("SO KPI Error:", err.message);
    return res.status(500).json({ error: "SO KPI query failed.", detail: err.message });
  }
});

// GET /api/kpi/invoices?from=&to=
app.get("/api/kpi/invoices", authMiddleware, async (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error: "from and to required." });
  try {
    const db     = await getPool();
    const result = await db.request()
      .input("from", sql.Date, from)
      .input("to",   sql.Date, to)
      .query(`
        -- Step 1: Get one row per InvNo with its summed SubTotal and status
        WITH IV_Summary AS (
          SELECT
            i.InvNo,
            SUM(i.Sub_Total)         AS SubTotalSum,
            MAX(hd.InvoiceStatus)    AS InvoiceStatus
          FROM vw_TodaysSalesInvoiceDetails i
          LEFT JOIN tCore_Header_0 h
            ON h.sVoucherNo = i.InvNo AND h.iVoucherType = 3332
          LEFT JOIN tCore_HeaderData3332_0 hd
            ON hd.iHeaderId = h.iHeaderId
          WHERE i.InvDate BETWEEN @from AND @to
          GROUP BY i.InvNo
        )
        SELECT
          COUNT(*)                                                 AS TotalCount,
          SUM(SubTotalSum)                                         AS TotalValue,
          SUM(CASE WHEN InvoiceStatus = 2 THEN 1 ELSE 0 END)      AS CancelledCount,
          SUM(CASE WHEN InvoiceStatus = 2 THEN SubTotalSum ELSE 0 END) AS CancelledValue
        FROM IV_Summary
      `);
    const r         = result.recordset[0];
    const total     = r.TotalCount     || 0;
    const cancelled = r.CancelledCount || 0;
    const active    = total - cancelled;
    const totalVal  = parseFloat(r.TotalValue)     || 0;
    const cancVal   = parseFloat(r.CancelledValue) || 0;
    return res.json({
      totalCount:       total,
      activeCount:      active,
      cancelledCount:   cancelled,
      totalValue:       totalVal,
      activeValue:      totalVal - cancVal,
      cancelledValue:   cancVal,
      activeRate:       total > 0 ? (active    / total * 100).toFixed(1) : "0.0",
      cancellationRate: total > 0 ? (cancelled / total * 100).toFixed(1) : "0.0",
    });
  } catch (err) {
    console.error("IV KPI Error:", err.message);
    return res.status(500).json({ error: "Invoice KPI query failed.", detail: err.message });
  }
});

// ── Health ─────────────────────────────────────────────────────────────────
app.get("/api/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

// ── Catch-all → frontend ───────────────────────────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  console.log(`🚀 POD System v2 running on port ${PORT}`);
  await ensureUsersTable();
});
