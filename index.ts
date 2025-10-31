import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  exchangeCodeForSessionToken,
  getOAuthRedirectUrl,
  authMiddleware,
  deleteSession,
  MOCHA_SESSION_TOKEN_COOKIE_NAME,
} from "@getmocha/users-service/backend";
import { getCookie, setCookie } from "hono/cookie";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";

const app = new Hono<{ Bindings: Env }>();

// Enable CORS for all routes
app.use("*", cors({
  origin: (origin) => origin,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// OAuth Routes
app.get('/api/oauth/google/redirect_url', async (c) => {
  const redirectUrl = await getOAuthRedirectUrl('google', {
    apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL,
    apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY,
  });

  return c.json({ redirectUrl }, 200);
});

app.post("/api/sessions", zValidator("json", z.object({ code: z.string() })), async (c) => {
  const { code } = c.req.valid("json");

  const sessionToken = await exchangeCodeForSessionToken(code, {
    apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL,
    apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY,
  });

  setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, sessionToken, {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: true,
    maxAge: 60 * 24 * 60 * 60, // 60 days
  });

  return c.json({ success: true }, 200);
});

app.get('/api/logout', async (c) => {
  const sessionToken = getCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME);

  if (typeof sessionToken === 'string') {
    await deleteSession(sessionToken, {
      apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL,
      apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY,
    });
  }

  setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, '', {
    httpOnly: true,
    path: '/',
    sameSite: 'none',
    secure: true,
    maxAge: 0,
  });

  return c.json({ success: true }, 200);
});

// User Management Routes
app.get("/api/users/me", authMiddleware, async (c) => {
  const mochaUser = c.get("user");
  
  if (!mochaUser) {
    return c.json({ error: "User not authenticated" }, 401);
  }
  
  // Check if user exists in our local database
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM users WHERE mocha_user_id = ?"
  ).bind(mochaUser.id).all();

  let localUser = results[0];

  // If user doesn't exist locally, create them as an agent by default
  if (!localUser) {
    const insertResult = await c.env.DB.prepare(
      `INSERT INTO users (mocha_user_id, email, full_name, role, profile_picture) 
       VALUES (?, ?, ?, ?, ?)`
    ).bind(
      mochaUser!.id,
      mochaUser!.email,
      mochaUser!.google_user_data.name || mochaUser!.email,
      'agent', // Default role
      mochaUser!.google_user_data.picture
    ).run();

    // Fetch the newly created user
    const { results: newUserResults } = await c.env.DB.prepare(
      "SELECT * FROM users WHERE id = ?"
    ).bind(insertResult.meta.last_row_id).all();
    
    localUser = newUserResults[0];
  }

  return c.json({ 
    ...mochaUser!, 
    localUser: {
      id: localUser.id,
      role: localUser.role,
      full_name: localUser.full_name,
      phone: localUser.phone,
      profile_picture: localUser.profile_picture,
      is_active: localUser.is_active
    }
  });
});

// Agent Management Routes (Manager only)
app.get("/api/agents", authMiddleware, async (c) => {
  const mochaUser = c.get("user");
  
  if (!mochaUser) {
    return c.json({ error: "User not authenticated" }, 401);
  }
  
  // Get current user's role
  const { results: userResults } = await c.env.DB.prepare(
    "SELECT role FROM users WHERE mocha_user_id = ?"
  ).bind(mochaUser!.id).all();

  if (!userResults[0] || userResults[0].role !== 'manager') {
    return c.json({ error: "Unauthorized. Manager access required." }, 403);
  }

  const { results } = await c.env.DB.prepare(
    "SELECT * FROM users ORDER BY created_at DESC"
  ).all();

  return c.json(results);
});

app.put("/api/agents/:id/role", authMiddleware, zValidator("json", z.object({ 
  role: z.enum(['manager', 'agent']) 
})), async (c) => {
  const mochaUser = c.get("user");
  const agentId = c.req.param("id");
  const { role } = c.req.valid("json");
  
  if (!mochaUser) {
    return c.json({ error: "User not authenticated" }, 401);
  }
  
  // Check if current user is manager
  const { results: userResults } = await c.env.DB.prepare(
    "SELECT role FROM users WHERE mocha_user_id = ?"
  ).bind(mochaUser!.id).all();

  if (!userResults[0] || userResults[0].role !== 'manager') {
    return c.json({ error: "Unauthorized. Manager access required." }, 403);
  }

  await c.env.DB.prepare(
    "UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
  ).bind(role, agentId).run();

  return c.json({ success: true });
});

// Contact Management Routes
app.get("/api/contacts", authMiddleware, async (c) => {
  const mochaUser = c.get("user");
  
  if (!mochaUser) {
    return c.json({ error: "User not authenticated" }, 401);
  }
  
  // Get current user's role and id
  const { results: userResults } = await c.env.DB.prepare(
    "SELECT id, role FROM users WHERE mocha_user_id = ?"
  ).bind(mochaUser!.id).all();

  if (!userResults[0]) {
    return c.json({ error: "User not found" }, 404);
  }

  const currentUser = userResults[0];
  let query = "SELECT * FROM contacts";
  let params = [];

  // If agent, only show assigned contacts
  if (currentUser.role === 'agent') {
    query += " WHERE assigned_agent_id = ?";
    params.push(currentUser.id);
  }

  query += " ORDER BY created_at DESC";
  
  const { results } = await c.env.DB.prepare(query).bind(...params).all();
  return c.json(results);
});

app.post("/api/contacts", authMiddleware, zValidator("json", z.object({
  name: z.string(),
  phone: z.string(),
  email: z.string().optional(),
  company: z.string().optional(),
  tags: z.string().optional(),
  notes: z.string().optional(),
})), async (c) => {
  const mochaUser = c.get("user");
  const contactData = c.req.valid("json");
  
  if (!mochaUser) {
    return c.json({ error: "User not authenticated" }, 401);
  }
  
  // Get current user's local id
  const { results: userResults } = await c.env.DB.prepare(
    "SELECT id FROM users WHERE mocha_user_id = ?"
  ).bind(mochaUser!.id).all();

  if (!userResults[0]) {
    return c.json({ error: "User not found" }, 404);
  }

  const result = await c.env.DB.prepare(
    `INSERT INTO contacts (name, phone, email, company, tags, notes, created_by_user_id) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    contactData.name,
    contactData.phone,
    contactData.email,
    contactData.company,
    contactData.tags,
    contactData.notes,
    userResults[0].id
  ).run();

  return c.json({ id: result.meta.last_row_id, success: true }, 201);
});

// Dashboard Routes
app.get("/api/dashboard/metrics", authMiddleware, async (c) => {
  const mochaUser = c.get("user");
  
  if (!mochaUser) {
    return c.json({ error: "User not authenticated" }, 401);
  }
  
  // Get current user's role and id
  const { results: userResults } = await c.env.DB.prepare(
    "SELECT id, role FROM users WHERE mocha_user_id = ?"
  ).bind(mochaUser!.id).all();

  if (!userResults[0]) {
    return c.json({ error: "User not found" }, 404);
  }

  const currentUser = userResults[0];
  
  if (currentUser.role === 'manager') {
    // Manager sees all metrics
    const [contactsResult, conversationsResult, messagesResult, agentStatsResult] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) as count FROM contacts").all(),
      c.env.DB.prepare("SELECT COUNT(*) as count FROM conversations WHERE status = 'active'").all(),
      c.env.DB.prepare("SELECT COUNT(*) as count FROM messages").all(),
      c.env.DB.prepare(`
        SELECT 
          u.id,
          u.full_name,
          COUNT(DISTINCT c.id) as totalContacts,
          COUNT(DISTINCT conv.id) as activeConversations,
          COUNT(DISTINCT m.id) as totalMessages
        FROM users u
        LEFT JOIN contacts c ON c.assigned_agent_id = u.id
        LEFT JOIN conversations conv ON conv.assigned_agent_id = u.id AND conv.status = 'active'
        LEFT JOIN messages m ON m.sender_type = 'agent' AND m.sender_id = u.id
        WHERE u.role = 'agent'
        GROUP BY u.id, u.full_name
        ORDER BY totalContacts DESC
      `).all()
    ]);

    return c.json({
      totalContacts: contactsResult.results[0]?.count || 0,
      activeConversations: conversationsResult.results[0]?.count || 0,
      totalMessages: messagesResult.results[0]?.count || 0,
      agentStats: agentStatsResult.results || []
    });
  } else {
    // Agent sees only their metrics
    const [contactsResult, conversationsResult, messagesResult] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) as count FROM contacts WHERE assigned_agent_id = ?").bind(currentUser.id).all(),
      c.env.DB.prepare("SELECT COUNT(*) as count FROM conversations WHERE assigned_agent_id = ? AND status = 'active'").bind(currentUser.id).all(),
      c.env.DB.prepare("SELECT COUNT(*) as count FROM messages WHERE sender_type = 'agent' AND sender_id = ?").bind(currentUser.id).all(),
    ]);

    return c.json({
      totalContacts: contactsResult.results[0]?.count || 0,
      activeConversations: conversationsResult.results[0]?.count || 0,
      totalMessages: messagesResult.results[0]?.count || 0,
    });
  }
});

export default app;
