require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.status(200).send("NearKart Admin Backend is Running!");
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const PORT = Number(process.env.PORT || 6000);
const JWT_SECRET = process.env.JWT_SECRET || "change-me";


// ============================================================
// GMAIL
// ============================================================

// ============================================================
// GMAIL CONFIGURATION
// ============================================================

let transporter = null;

if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
  transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    }
  });
}

  console.log("Gmail SMTP configured");

} else {
  console.error("Gmail environment variables missing");
}

// ============================================================
// BASIC HELPERS
// ============================================================

function hashCode(code) {
  return crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
}


// ============================================================
// AUTH
// ============================================================

function auth(req, res, next) {
  const h = req.headers.authorization || "";

  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  try {
    req.user = jwt.verify(
      h.slice(7),
      JWT_SECRET
    );

    next();

  } catch (e) {

    return res.status(401).json({
      error: "Invalid token"
    });

  }
}


// ============================================================
// ADMIN
// ============================================================

function admin(req, res, next) {

  if (!req.user || req.user.role !== "admin") {

    return res.status(403).json({
      error: "Admin only"
    });

  }

  next();
}


// ============================================================
// DATABASE HELPERS
// ============================================================

async function ensureColumns() {

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_hash TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS phone TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS account_status VARCHAR(30)
  `);

  await pool.query(`
    UPDATE users
    SET account_status = COALESCE(status::text, 'active')
    WHERE account_status IS NULL
  `);
}


// ============================================================
// OTP EMAIL
// ============================================================

async function sendOtp(email, code, purpose) {
  if (!transporter) {
    throw new Error("Gmail configuration missing");
  }

  try {
    const info = await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: `NearKart ${purpose} OTP`,
      text: `Your NearKart OTP is ${code}. Valid for 5 minutes.`
    });

    console.log("OTP sent:", info.messageId);
    return info;
  } catch (error) {
    console.error("Gmail OTP error:", error);
    throw error;
  }
}

// ============================================================
// HEALTH
// ============================================================

app.get(
  "/api/health",
  async (req, res) => {

    try {

      await pool.query("SELECT 1");

      await ensureColumns();

      res.json({

        ok: true,

        db: true,

        port: PORT,

        version: "5.0.0-clean"

      });

    } catch (e) {

      console.error(
        "Health error:",
        e
      );

      res.status(500).json({

        ok: false,

        db: false,

        error: e.message

      });

    }

  }
);


// ============================================================
// REQUEST OTP
// ============================================================

app.post(
  "/api/auth/request-otp",
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ""
        )
        .toLowerCase()
        .trim();

      const purpose =
        req.body.purpose || "login";


      if (!email) {

        return res.status(400).json({
          error: "Email required"
        });

      }


      if (
        ![
          "login",
          "forgot_password"
        ].includes(purpose)
      ) {

        return res.status(400).json({
          error: "Invalid OTP purpose"
        });

      }


      const user =
        await pool.query(

          `
          SELECT id
          FROM users
          WHERE lower(email)=lower($1)
          AND role='admin'
          LIMIT 1
          `,

          [email]

        );


      if (
        purpose === "forgot_password" &&
        !user.rowCount
      ) {

        return res.status(404).json({

          error:
            "Admin account not found"

        });

      }


      const code =
        String(
          Math.floor(
            100000 +
            Math.random() * 900000
          )
        );


      await pool.query(

        `
        INSERT INTO otp_codes
        (
          email,
          purpose,
          code_hash,
          expires_at,
          used
        )
        VALUES
        (
          $1,
          $2,
          $3,
          NOW()+INTERVAL '5 minutes',
          false
        )
        `,

        [
          email,
          purpose,
          hashCode(code)
        ]

      );


      await sendOtp(
        email,
        code,
        purpose
      );


      res.json({

        message:
          "OTP sent to Gmail"

      });


    } catch (e) {

      console.error(
        "Request OTP error:",
        e
      );

      res.status(500).json({

        error:
          e.message

      });

    }

  }
);


// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      await ensureColumns();


      const email =
        String(
          req.body.email || ""
        )
        .toLowerCase()
        .trim();


      const code =
        String(
          req.body.otp ||
          req.body.code ||
          ""
        ).trim();


      const qUser =
        await pool.query(

          `
          SELECT
            id,
            email,
            name,
            role,
            password_hash,
            phone
          FROM users
          WHERE lower(email)=lower($1)
          AND role='admin'
          LIMIT 1
          `,

          [email]

        );


      if (!qUser.rowCount) {

        return res.status(404).json({

          error:
            "Admin account not found"

        });

      }


      const user =
        qUser.rows[0];


      if (!user.password_hash) {

        return res.status(400).json({

          error:
            "This account has no password set"

        });

      }


      const qOtp =
        await pool.query(

          `
          SELECT id
          FROM otp_codes
          WHERE email=$1
          AND purpose='login'
          AND used=false
          AND expires_at>NOW()
          AND code_hash=$2
          ORDER BY id DESC
          LIMIT 1
          `,

          [
            email,
            hashCode(code)
          ]

        );


      if (!qOtp.rowCount) {

        return res.status(400).json({

          error:
            "Invalid or expired OTP"

        });

      }


      const token =
        jwt.sign(

          {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role
          },

          JWT_SECRET,

          {
            expiresIn: "12h"
          }

        );


      await pool.query(

        `
        UPDATE otp_codes
        SET used=true
        WHERE id=$1
        `,

        [qOtp.rows[0].id]

      );


      delete user.password_hash;


      res.json({

        verified: true,

        token,

        user

      });


    } catch (e) {

      console.error(
        "Login error:",
        e
      );

      res.status(500).json({

        error:
          e.message

      });

    }

  }
);


// ============================================================
// CUSTOMERS
// ============================================================

async function getCustomers(req, res) {

  try {

    await ensureColumns();


    const q =
      await pool.query(`

        SELECT

          u.id,
          u.name,
          u.email,
          u.phone,
          u.role,

          COALESCE(
            u.account_status,
            u.status::text,
            'active'
          ) AS account_status,

          u.created_at

        FROM users u

        WHERE u.role='customer'

        ORDER BY
          u.created_at DESC NULLS LAST

        LIMIT 1000

      `);


    res.json(q.rows);


  } catch (e) {

    console.error(
      "Customers error:",
      e
    );

    res.status(500).json({
      error: e.message
    });

  }

}


app.get(
  "/api/customers",
  auth,
  admin,
  getCustomers
);

app.get(
  "/api/admin/customers",
  auth,
  admin,
  getCustomers
);


// ============================================================
// SHOPKEEPERS
// ============================================================

async function getShopkeepers(req, res) {

  try {

    await ensureColumns();


    const q =
      await pool.query(`

        SELECT

          u.id,
          u.name,
          u.email,
          u.phone,
          u.role,

          COALESCE(
            sp.approval_status::text,
            s.status::text,
            u.account_status,
            u.status::text,
            'unknown'
          ) AS status,

          COALESCE(
            u.account_status,
            u.status::text,
            'active'
          ) AS account_status,

          u.created_at,

          s.id AS shop_id,
          s.shop_name,
          s.category,
          s.gst_number,
          s.pan_number,

          s.status AS shop_status,

          sp.approval_status
          AS profile_approval_status

        FROM users u

        LEFT JOIN shops s
          ON s.owner_id=u.id

        LEFT JOIN shopkeeper_profiles sp
          ON sp.user_id=u.id

        WHERE u.role='shopkeeper'

        ORDER BY
          u.created_at DESC NULLS LAST

        LIMIT 1000

      `);


    res.json(q.rows);


  } catch (e) {

    console.error(
      "Shopkeepers error:",
      e
    );

    res.status(500).json({

      error:
        e.message

    });

  }

}


app.get(
  "/api/shopkeepers",
  auth,
  admin,
  getShopkeepers
);

app.get(
  "/api/admin/shopkeepers",
  auth,
  admin,
  getShopkeepers
);


// ============================================================
// DELIVERY
// ============================================================

async function getDelivery(req, res) {

  try {

    await ensureColumns();


    const q =
      await pool.query(`

        SELECT

          u.id,
          u.name,
          u.email,
          u.phone,
          u.role,

          COALESCE(
            u.account_status,
            u.status::text,
            'active'
          ) AS account_status,

          u.created_at,

          dp.id AS delivery_partner_id,

          dp.approval_status,

          dp.is_online,

          dp.current_latitude,

          dp.current_longitude

        FROM users u

        LEFT JOIN delivery_partners dp
          ON dp.user_id=u.id

        WHERE u.role
        IN ('delivery','delivery_boy')

        ORDER BY
          u.created_at DESC NULLS LAST

        LIMIT 1000

      `);


    res.json(q.rows);


  } catch (e) {

    console.error(
      "Delivery error:",
      e
    );

    res.status(500).json({

      error:
        e.message

    });

  }

}


app.get(
  "/api/delivery",
  auth,
  admin,
  getDelivery
);

app.get(
  "/api/admin/delivery",
  auth,
  admin,
  getDelivery
);


// ============================================================
// USER STATUS
// IMPORTANT:
// account_status ko same $1 ke saath update nahi kar rahe.
// Isi se PostgreSQL inconsistent parameter type error
// avoid hota hai.
// ============================================================

async function updateUserStatus(
  id,
  status
) {

  const q =
    await pool.query(

      `
      UPDATE users

      SET status=$1

      WHERE id=$2

      RETURNING
        id,
        email,
        name,
        role,
        status,
        account_status
      `,

      [
        status,
        id
      ]

    );


  if (!q.rowCount) {

    throw new Error(
      "User not found"
    );

  }


  // account_status VARCHAR hai.
  // Isko separate query mein update kar rahe hain.

  await pool.query(

    `
    UPDATE users

    SET account_status=$1::varchar

    WHERE id=$2
    `,

    [
      String(status),
      id
    ]

  );


  return q.rows[0];

}


// ============================================================
// SHOPKEEPER UPDATE
// ============================================================

async function updateShopkeeper(
  id,
  action
) {

  const map = {
    accept: "approved",
    reject: "rejected",
    suspend: "suspended",
    activate: "active"
  };

  const approvalStatus =
    map[action];

  if (!approvalStatus) {
    throw new Error(
      "Invalid shopkeeper action"
    );
  }

  let userStatus;

  if (
    action === "accept" ||
    action === "activate"
  ) {
    userStatus = "active";
  } else if (
    action === "reject"
  ) {
    userStatus = "inactive";
  } else {
    userStatus = "suspended";
  }

  const user =
    await updateUserStatus(
      id,
      userStatus
    );

  // Update shopkeeper profile
  await pool.query(
    `
    UPDATE shopkeeper_profiles
    SET approval_status=$1
    WHERE user_id=$2
    `,
    [
      approvalStatus,
      id
    ]
  );

  // approved_at
  if (
    approvalStatus === "approved"
  ) {

    await pool.query(
      `
      UPDATE shopkeeper_profiles
      SET approved_at=NOW()
      WHERE user_id=$1
      `,
      [id]
    );

  }

  // Update shop
  let shopStatus;

  if (action === "accept") {
    shopStatus = "approved";
  } else if (action === "activate") {
    shopStatus = "active";
  } else {
    shopStatus = approvalStatus;
  }

  await pool.query(
    `
    UPDATE shops
    SET status=$1
    WHERE owner_id=$2
    `,
    [
      shopStatus,
      id
    ]
  );

  return user;
}


// ============================================================
// DELIVERY UPDATE
// ============================================================

async function updateDelivery(
  id,
  action
) {

  const map = {

    accept: "approved",

    reject: "rejected",

    suspend: "suspended",

    activate: "active"

  };


  const approvalStatus =
    map[action];


  if (!approvalStatus) {

    throw new Error(
      "Invalid delivery action"
    );

  }


  let userStatus;


  if (
    action === "accept" ||
    action === "activate"
  ) {

    userStatus = "active";

  } else if (
    action === "reject"
  ) {

    userStatus = "inactive";

  } else {

    userStatus = "suspended";

  }


  const user =
    await updateUserStatus(
      id,
      userStatus
    );


  await pool.query(

    `
    UPDATE delivery_partners

    SET approval_status=$1

    WHERE user_id=$2
    `,

    [
      approvalStatus,
      id
    ]

  );


  return user;

}


// ============================================================
// SHOPKEEPER ACTION HANDLER
// ============================================================

async function shopkeeperAction(
  req,
  res
) {

  try {

    const id =
      req.params.id;


    const action =
      req.params.action;


    const validActions = [
      "accept",
      "reject",
      "suspend",
      "activate"
    ];


    if (
      !validActions.includes(action)
    ) {

      return res.status(400).json({

        error:
          "Invalid action"

      });

    }


    const user =
      await updateShopkeeper(
        id,
        action
      );


    res.json({

      success: true,

      message:
        `Shopkeeper ${action} successful`,

      user

    });


  } catch (e) {

    console.error(
      "Shopkeeper action error:",
      e
    );


    res.status(500).json({

      error:
        e.message

    });

  }

}


// ============================================================
// SHOPKEEPER ACTION ROUTES
// ============================================================

app.post(
  "/api/shopkeepers/:id/:action",
  auth,
  admin,
  shopkeeperAction
);

app.post(
  "/api/admin/shopkeepers/:id/:action",
  auth,
  admin,
  shopkeeperAction
);


// ============================================================
// DELIVERY ACTION
// ============================================================

async function deliveryAction(
  req,
  res
) {

  try {

    const id =
      req.params.id;


    const action =
      req.params.action;


    const validActions = [
      "accept",
      "reject",
      "suspend",
      "activate"
    ];


    if (
      !validActions.includes(action)
    ) {

      return res.status(400).json({

        error:
          "Invalid action"

      });

    }


    const user =
      await updateDelivery(
        id,
        action
      );


    res.json({

      success: true,

      message:
        `Delivery ${action} successful`,

      user

    });


  } catch (e) {

    console.error(
      "Delivery action error:",
      e
    );


    res.status(500).json({

      error:
        e.message

    });

  }

}


app.post(
  "/api/delivery/:id/:action",
  auth,
  admin,
  deliveryAction
);

app.post(
  "/api/admin/delivery/:id/:action",
  auth,
  admin,
  deliveryAction
);


// ============================================================
// CUSTOMER BLOCK / UNBLOCK
// ============================================================

app.post(
  "/api/customers/:id/:action",
  auth,
  admin,
  async (req, res) => {

    try {

      const id =
        req.params.id;

      const action =
        req.params.action;


      let status;


      if (action === "block") {

        status = "blocked";

      } else if (
        action === "unblock"
      ) {

        status = "active";

      } else {

        return res.status(400).json({

          error:
            "Invalid customer action"

        });

      }


      const user =
        await updateUserStatus(
          id,
          status
        );


      res.json({

        success: true,

        message:
          `Customer ${action} successful`,

        user

      });


    } catch (e) {

      console.error(
        "Customer action error:",
        e
      );


      res.status(500).json({

        error:
          e.message

      });

    }

  }
);


// ============================================================
// ADMIN SHOPKEEPER MESSAGE
// ============================================================

app.post(
  "/api/admin/shopkeepers/:id/message",
  auth,
  admin,
  async (req, res) => {

    try {

      const id =
        req.params.id;


      const message =
        String(
          req.body.message || ""
        ).trim();


      if (!message) {

        return res.status(400).json({

          error:
            "Message required"

        });

      }


      const q =
        await pool.query(

          `
          SELECT
            id,
            name,
            email,
            phone

          FROM users

          WHERE id=$1

          AND role='shopkeeper'

          LIMIT 1
          `,

          [id]

        );


      if (!q.rowCount) {

        return res.status(404).json({

          error:
            "Shopkeeper not found"

        });

      }


      const user =
        q.rows[0];


      // Email message if Gmail configured

      if (transporter) {

        await transporter.sendMail({

          from:
            process.env.GMAIL_USER,

          to:
            user.email,

          subject:
            "NearKart Admin Message",

          text:
            message

        });

      } else {

        console.log(
          `[ADMIN MESSAGE] ${user.email}: ${message}`
        );

      }


      res.json({

        success: true,

        message:
          "Message sent successfully"

      });


    } catch (e) {

      console.error(
        "Message error:",
        e
      );


      res.status(500).json({

        error:
          e.message

      });

    }

  }
);


// ============================================================
// DASHBOARD
// ============================================================

app.get(
  "/api/dashboard",
  auth,
  admin,
  async (req, res) => {

    try {

      const q =
        await Promise.all([

          pool.query(`
            SELECT COUNT(*)::int AS c
            FROM users
            WHERE role='customer'
          `),

          pool.query(`
            SELECT COUNT(*)::int AS c
            FROM users
            WHERE role='shopkeeper'
          `),

          pool.query(`
            SELECT COUNT(*)::int AS c
            FROM users
            WHERE role
            IN ('delivery','delivery_boy')
          `),

          pool.query(`
            SELECT COUNT(*)::int AS c
            FROM shops
          `),

          pool.query(`
            SELECT COUNT(*)::int AS c
            FROM orders
          `)

        ]);


      res.json({

        customers:
          q[0].rows[0].c,

        shopkeepers:
          q[1].rows[0].c,

        delivery:
          q[2].rows[0].c,

        shops:
          q[3].rows[0].c,

        orders:
          q[4].rows[0].c

      });


    } catch (e) {

      console.error(
        "Dashboard error:",
        e
      );


      res.status(500).json({

        error:
          e.message

      });

    }

  }
);


// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {

    res.status(404).json({

      error:
        `Cannot ${req.method} ${req.originalUrl}`

    });

  }
);


// ============================================================
// SERVER START
// IMPORTANT: app.listen MUST BE LAST
// ============================================================

app.listen(
  PORT,
  async () => {

    console.log(
      `NearKart Admin Backend running on port ${PORT}`
    );


    try {

      await pool.query(
        "SELECT 1"
      );


      await ensureColumns();


      console.log(
        "Database connected successfully"
      );


    } catch (e) {

      console.error(
        "Database connection failed:",
        e.message
      );

    }

  }
);