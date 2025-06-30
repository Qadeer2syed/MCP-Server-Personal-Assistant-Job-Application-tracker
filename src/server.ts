
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer } from 'http';
import open from 'open';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface MeetingInfo {
  id: string;
  title: string;
  startTime: string;
  endTime: string;
  attendees: string[];
  location?: string;
  meetingLink?: string;
}

interface EmailInfo {
  id: string;
  subject: string;
  sender: string;
  snippet: string;
  date: string;
  body?: string; // Optional body field
  isImportant: boolean;
  hasDeadline: boolean;
}

interface TokenData {
  access_token: string;
  refresh_token: string;
  scope: string;
  token_type: string;
  expiry_date: number;
}

class PersonalAssistantMCPServer {
  private server: Server;
  private googleAuth!: OAuth2Client;
  private calendar: any;
  private gmail: any;
  private sheets: any;
  private tokenPath: string;
  private isAuthenticated = false;
  private spreadsheetId = process.env.SPREADSHEET_ID;

  
  // Pre-configured OAuth credentials (you provide these)
  private readonly OAUTH_CONFIG = {
    CLIENT_ID: process.env.GOOGLE_CLIENT_ID || 'your-preconfigured-client-id',
    CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || 'your-preconfigured-client-secret',
    REDIRECT_URI: 'http://localhost:8080/auth/callback'
  };

  constructor() {
    this.server = new Server(
      {
        name: 'personal-assistant',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
          resources: {},
        },
      }
    );

    this.tokenPath = path.join(__dirname, 'user-tokens.json');
    this.setupGoogleAuth();
    this.setupToolHandlers();
  }

  private setupGoogleAuth() {
    this.googleAuth = new OAuth2Client(
      this.OAUTH_CONFIG.CLIENT_ID,
      this.OAUTH_CONFIG.CLIENT_SECRET,
      this.OAUTH_CONFIG.REDIRECT_URI
    );

    // Set up automatic token refresh
    this.googleAuth.on('tokens', (tokens) => {
      if (tokens.refresh_token) {
        this.saveTokens(tokens);
      }
    });

    this.calendar = google.calendar({ version: 'v3', auth: this.googleAuth });
    this.gmail = google.gmail({ version: 'v1', auth: this.googleAuth });
    this.sheets = google.sheets({ version: 'v4', auth: this.googleAuth });

  }

  private async loadTokens(): Promise<TokenData | null> {
    try {
      const tokenData = await fs.readFile(this.tokenPath, 'utf8');
      return JSON.parse(tokenData);
    } catch (error) {
      return null;
    }
  }

  private async saveTokens(tokens: any): Promise<void> {
    try {
      await fs.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2));
      console.error('✅ Login saved! You won\'t need to login again.');
    } catch (error) {
      console.error('Error saving login:', error);
    }
  }

  private async quickLogin(): Promise<boolean> {
    // Check if user is already logged in
    const savedTokens = await this.loadTokens();
    
    if (savedTokens) {
      this.googleAuth.setCredentials(savedTokens);
      
      try {
        await this.googleAuth.getAccessToken();
        this.isAuthenticated = true;
        console.error('✅ Already logged in!');
        return true;
      } catch (error) {
        console.error('🔄 Login expired, need to login again...');
      }
    }

    // Start simple login flow
    return await this.startSimpleLogin();
  }

  private async startSimpleLogin(): Promise<boolean> {
    return new Promise((resolve) => {
      const scopes = [
        'https://www.googleapis.com/auth/calendar.readonly',
        'https://www.googleapis.com/auth/calendar.events.readonly',
        'https://www.googleapis.com/auth/gmail.readonly',        // Added for Gmail read access
        'https://www.googleapis.com/auth/gmail.metadata',
        'https://www.googleapis.com/auth/spreadsheets'
      ];

      const authUrl = this.googleAuth.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        prompt: 'consent',
        include_granted_scopes: true
      });

      console.error('\n🔐 GOOGLE LOGIN REQUIRED');
      console.error('Opening login page in your browser...');
      console.error('If it doesn\'t open automatically, copy this URL:');
      console.error(authUrl);
      console.error('');

      // Automatically open browser
      open(authUrl).catch(() => {
        console.error('Could not open browser automatically. Please copy the URL above.');
      });

      // Create a simple callback server
      const server = createServer(async (req, res) => {
        if (req.url?.startsWith('/auth/callback')) {
          const url = new URL(req.url, `http://${req.headers.host}`);
          const code = url.searchParams.get('code');
          const error = url.searchParams.get('error');

          if (error) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <head><title>Login Failed</title></head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                  <h1>❌ Login Failed</h1>
                  <p>Error: ${error}</p>
                  <p>Please try again.</p>
                </body>
              </html>
            `);
            server.close();
            resolve(false);
            return;
          }

          if (code) {
            try {
              const { tokens } = await this.googleAuth.getToken(code);
              this.googleAuth.setCredentials(tokens);
              await this.saveTokens(tokens);
              
              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end(`
                <html>
                  <head><title>Login Successful</title></head>
                  <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>✅ Login Successful!</h1>
                    <p>You're now connected to Google Calendar.</p>
                    <p>You can close this window and return to your application.</p>
                    <script>
                      setTimeout(() => {
                        window.close();
                      }, 3000);
                    </script>
                  </body>
                </html>
              `);
              
              this.isAuthenticated = true;
              console.error('✅ Login successful!');
              server.close();
              resolve(true);
            } catch (error) {
              console.error('Login error:', error);
              res.writeHead(500, { 'Content-Type': 'text/html' });
              res.end(`
                <html>
                  <head><title>Login Error</title></head>
                  <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>❌ Login Error</h1>
                    <p>Something went wrong. Please try again.</p>
                  </body>
                </html>
              `);
              server.close();
              resolve(false);
            }
          }
        } else {
          res.writeHead(404);
          res.end('Not Found');
        }
      });

      // Find available port starting from 8080
      this.startServerOnAvailablePort(server, 8080, (port) => {
        console.error(`Waiting for login... (server running on port ${port})`);
      });

      // Timeout after 3 minutes
      setTimeout(() => {
        server.close();
        console.error('⏰ Login timed out. Please try again.');
        resolve(false);
      }, 3 * 60 * 1000);
    });
  }

  private startServerOnAvailablePort(server: any, startPort: number, callback: (port: number) => void) {
    server.listen(startPort, () => {
      callback(startPort);
    }).on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        this.startServerOnAvailablePort(server, startPort + 1, callback);
      } else {
        console.error('Server error:', err);
      }
    });
  }

  private async ensureLoggedIn(): Promise<boolean> {
    if (this.isAuthenticated) {
      return true;
    }
    
    console.error('🔐 Google login required...');
    return await this.quickLogin();
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'login_google',
          description: 'Login to Google (one-time setup, saves credentials)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_upcoming_meetings',
          description: 'Get upcoming calendar meetings for today or specified date range',
          inputSchema: {
            type: 'object',
            properties: {
              timeMin: {
                type: 'string',
                description: 'Start date/time (ISO format, defaults to now)',
              },
              timeMax: {
                type: 'string',
                description: 'End date/time (ISO format, defaults to end of day)',
              },
              maxResults: {
                type: 'number',
                description: 'Maximum number of meetings to return (default: 10)',
                default: 10,
              },
            },
          },
        },
        {
          name: 'check_emails',
          description: 'Check for emails for the past 24 hours. Check the email body nd content thoroughly and analyze content from it',
          inputSchema: {
            type: 'object',
            properties: {
              maxResults: {
                type: 'number',
                description: 'Maximum number of emails to check (default: 100)',
                default: 10,
              },
              hoursBack: {
                type: 'number',
                description: 'Hours to look back for emails (default: 24)',
                default: 24,
              },
            },
          },
        },
        {
          name: 'check_login_status',
          description: 'Check if logged in to Google',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'logout',
          description: 'Logout from Google (clears saved credentials)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
        name: 'add_job_application',
        description: 'Record a new job application in Sheets. However, check if this job sis already present in the sheet. Do not add duplicate entries. First check the list of applications for existing applications',
        inputSchema: {
            type: 'object',
            properties: {
            spreadsheetId: { type: 'string' },
            jobTitle: { type: 'string' },
            company: { type: 'string' },
            dateApplied: { type: 'string' },     // ISO date
            status: { type: 'string' }           // e.g. "Applied"
            },
            required: ['spreadsheetId', 'jobTitle', 'company', 'dateApplied']
        }
        },
        {
        name: 'update_job_status',
        description: 'Update status of an existing job application. Check the email body if any email has rejection or acceptance and update the existing job applications accordingly. Check from the list of applications for current ones.',
        inputSchema: {
            type: 'object',
            properties: {
            spreadsheetId: { type: 'string' },
            jobTitle: { type: 'string' },
            newStatus: { type: 'string' }
            },
            required: ['spreadsheetId', 'jobTitle', 'newStatus']
        }
        },
        {
        name: 'list_applications',
        description: 'List all tracked job applications',
        inputSchema: {
            type: 'object',
            properties: {
            spreadsheetId: { type: 'string' }
            },
            required: ['spreadsheetId']
        }
        }

      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'login_google':
            return await this.handleLogin();
          
          case 'get_upcoming_meetings':
            return await this.getUpcomingMeetings(args as any);

          case 'check_emails':
            return await this.checkEmails(args as any);

          case 'add_job_application':
            return await this.handleAddJobApplication(args as any);

          case 'update_job_status':
            return await this.handleUpdateJobStatus(args as any);

          case 'list_applications':
            return await this.handleListApplications(args as any);

          
          case 'check_login_status':
            return await this.checkLoginStatus();
          
          case 'logout':
            return await this.handleLogout();
          
          default:
            return {
              content: [
                {
                  type: 'text',
                  text: `Unknown tool: ${name}`,
                },
              ],
              isError: true,
            };
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${errorMessage}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async handleLogin() {
    const success = await this.quickLogin();
    
    return {
      content: [
        {
          type: 'text',
          text: success 
            ? '✅ Google login successful! You can now access your calendar.'
            : '❌ Google login failed. Please try again.',
        },
      ],
      isError: !success,
    };
  }

  private async checkLoginStatus() {
    let status = '❌ Not logged in';
    let loggedIn = false;

    if (this.isAuthenticated) {
      try {
        await this.googleAuth.getAccessToken();
        status = '✅ Logged in and ready';
        loggedIn = true;
      } catch (error) {
        status = '⚠️ Login expired, please login again';
        this.isAuthenticated = false;
      }
    }

    const hasTokenFile = Boolean(await this.loadTokens());

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ 
            status, 
            loggedIn,
            hasStoredCredentials: hasTokenFile
          }, null, 2),
        },
      ],
    };
  }

  private async handleLogout() {
    try {
      // Clear saved tokens
      await fs.unlink(this.tokenPath);
      this.isAuthenticated = false;
      this.googleAuth.setCredentials({});
      
      return {
        content: [
          {
            type: 'text',
            text: '✅ Logged out successfully. Saved credentials cleared.',
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: '✅ Logged out (no saved credentials found).',
          },
        ],
      };
    }
  }

  private async getUpcomingMeetings(args: {
    timeMin?: string;
    timeMax?: string;
    maxResults?: number;
  }) {
    // Automatically handle login if needed
    if (!(await this.ensureLoggedIn())) {
      return {
        content: [
          {
            type: 'text',
            text: '❌ Google login required. Please run "login_google" first.',
          },
        ],
        isError: true,
      };
    }

    const now = new Date();
    const timeMin = args.timeMin || now.toISOString();
    const timeMax = args.timeMax || new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();

    try {
      const response = await this.calendar.events.list({
        calendarId: 'primary',
        timeMin,
        timeMax,
        maxResults: args.maxResults || 10,
        singleEvents: true,
        orderBy: 'startTime',
      });

      const meetings: MeetingInfo[] = response.data.items?.map((event: any) => ({
        id: event.id,
        title: event.summary || 'No Title',
        startTime: event.start?.dateTime || event.start?.date,
        endTime: event.end?.dateTime || event.end?.date,
        attendees: event.attendees?.map((att: any) => att.email) || [],
        location: event.location,
        meetingLink: event.hangoutLink || event.conferenceData?.entryPoints?.[0]?.uri,
      })) || [];

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ 
              meetings, 
              count: meetings.length,
              timeRange: { from: timeMin, to: timeMax }
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      if (error instanceof Error && error.message.includes('invalid_grant')) {
        this.isAuthenticated = false;
        return {
          content: [
            {
              type: 'text',
              text: '🔄 Login expired. Please run "login_google" to login again.',
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }

  private async checkEmails(args: {
  maxResults?: number;
  hoursBack?: number;
  includeBody?: boolean; // New optional parameter
}) {
  // Add authentication check at the beginning
  if (!(await this.ensureLoggedIn())) {
    return {
      content: [
        {
          type: 'text',
          text: '❌ Google login required. Please run "login_google" first.',
        },
      ],
      isError: true,
    };
  }

  const hoursBack = args.hoursBack || 24;
  const after = Math.floor((Date.now() - hoursBack * 60 * 60 * 1000) / 1000);
  const includeBody = args.includeBody || false;

  try {
    const response = await this.gmail.users.messages.list({
      userId: 'me',
      q: ``, // Remove search query entirely,
      maxResults: args.maxResults || 10,
    });

    const emails: EmailInfo[] = [];
    
    if (response.data.messages) {
      for (const message of response.data.messages) {
        // Use 'full' format when body is requested, 'metadata' otherwise
        const format = includeBody ? 'full' : 'metadata';
        
        const emailDetails = await this.gmail.users.messages.get({
          userId: 'me',
          id: message.id,
          format: format,
          metadataHeaders: ['From', 'Subject', 'Date'],
        });

        const headers = emailDetails.data.payload?.headers || [];
        const subject = headers.find((h: any) => h.name === 'Subject')?.value || '';
        const from = headers.find((h: any) => h.name === 'From')?.value || '';
        const date = headers.find((h: any) => h.name === 'Date')?.value || '';

        // Extract email body if requested
        let body = '';
        if (includeBody && emailDetails.data.payload) {
          body = this.extractEmailBody(emailDetails.data.payload);
        }

        emails.push({
          id: message.id!,
          subject,
          sender: from,
          snippet: emailDetails.data.snippet || '',
          date,
          body: includeBody ? body : undefined, // Only include body if requested
          isImportant: emailDetails.data.labelIds?.includes('IMPORTANT') || false,
          hasDeadline: /deadline|due|asap|urgent|expires/i.test(subject + emailDetails.data.snippet),
        });
      }
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ emails, count: emails.length }, null, 2),
        },
      ],
    };
  } catch (error) {
    if (error instanceof Error && error.message.includes('invalid_grant')) {
      this.isAuthenticated = false;
      return {
        content: [
          {
            type: 'text',
            text: '🔄 Login expired. Please run "login_google" to login again.',
          },
        ],
        isError: true,
      };
    }
    throw error;
  }
}

// Helper method to extract email body from Gmail payload
private extractEmailBody(payload: any): string {
  let body = '';

  // Function to decode base64url
  const decodeBase64Url = (data: string): string => {
    // Replace URL-safe characters
    const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    return Buffer.from(padded, 'base64').toString('utf-8');
  };

  // Recursive function to extract text from multipart emails
  const extractText = (part: any): string => {
    let text = '';

    if (part.body?.data) {
      // Direct body content
      try {
        text += decodeBase64Url(part.body.data);
      } catch (error) {
        console.error('Error decoding email body:', error);
      }
    }

    if (part.parts) {
      // Multipart email - recursively process parts
      for (const subPart of part.parts) {
        // Prioritize text/plain, but also include text/html if no plain text
        if (subPart.mimeType === 'text/plain') {
          text += extractText(subPart);
        } else if (subPart.mimeType === 'text/html' && !text) {
          // Only use HTML if no plain text found
          const htmlContent = extractText(subPart);
          // Basic HTML tag removal (you might want to use a proper HTML parser)
          text += htmlContent.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
        } else if (subPart.parts) {
          // Nested multipart
          text += extractText(subPart);
        }
      }
    }

    return text;
    };

    body = extractText(payload);
    return body.trim();
    }

    private async handleAddJobApplication({
        spreadsheetId, jobTitle, company, dateApplied, status = 'Applied'
        }: {
        spreadsheetId: string;
        jobTitle: string;
        company: string;
        dateApplied: string;
        status?: string;
        }) {
        if (!(await this.ensureLoggedIn())) {
            return { content: [{ type: 'text', text: '❌ Please login first via login_google.' }], isError: true };
        }

        const row = [ jobTitle, company, dateApplied, status ];
        await this.sheets.spreadsheets.values.append({
            spreadsheetId,
            range: 'Applications!A:D',           // assumes a sheet named “Applications”
            valueInputOption: 'USER_ENTERED',
            requestBody: { values: [row] }
        });

        return { content: [{ type: 'text', text: `✅ Added application for “${jobTitle}” at ${company}.` }] };
        }

        private async handleUpdateJobStatus({
        spreadsheetId, jobTitle, newStatus
        }: {
        spreadsheetId: string;
        jobTitle: string;
        newStatus: string;
        }) {
        if (!(await this.ensureLoggedIn())) {
            return { content: [{ type: 'text', text: '❌ Please login first via login_google.' }], isError: true };
        }

        // 1. Fetch all rows
        const resp = await this.sheets.spreadsheets.values.get({
            spreadsheetId,
            range: 'Applications!A:D'
        });
        const rows = resp.data.values || [];

        // 2. Find the row index by jobTitle
        const rowIndex = rows.findIndex((r: any[]) => r[0] === jobTitle);
        if (rowIndex < 1) {  // rowIndex 0 is header
            return { content: [{ type: 'text', text: `❌ "${jobTitle}" not found.` }], isError: true };
        }

        // 3. Update the “Status” column (D)
        const range = `Applications!D${rowIndex + 1}`;
        await this.sheets.spreadsheets.values.update({
            spreadsheetId,
            range,
            valueInputOption: 'USER_ENTERED',
            requestBody: { values: [[newStatus]] }
        });

        return { content: [{ type: 'text', text: `✅ Updated status for “${jobTitle}” to "${newStatus}".` }] };
        }

        private async handleListApplications({ spreadsheetId }: { spreadsheetId: string }) {
        if (!(await this.ensureLoggedIn())) {
            return { content: [{ type: 'text', text: '❌ Please login first via login_google.' }], isError: true };
        }

        const resp = await this.sheets.spreadsheets.values.get({
            spreadsheetId,
            range: 'Applications!A:D'
        });
        const rows = resp.data.values || [];
        // Return as JSON text so your front‐end can render it
        return {
            content: [
            { type: 'text', text: JSON.stringify({ applications: rows.slice(1) }, null, 2) }
            ]
        };
    }

  
  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    console.error('🚀 Personal Assistant MCP Server running');
    console.error('');
    console.error('Available commands:');
    console.error('  • login_google       - Login to Google (one-time)');
    console.error('  • get_upcoming_meetings - Get your calendar events');
    console.error('  • check_login_status - Check if you\'re logged in');
    console.error('  • logout            - Clear saved login');
    console.error('');
    
    // Try to login automatically in the background
    this.quickLogin().then((success) => {
      if (success) {
        console.error('✅ Ready to use! You\'re already logged in.');
      } else {
        console.error('💡 Run "login_google" when you\'re ready to connect to Google Calendar');
      }
    }).catch(() => {
      console.error('💡 Run "login_google" to get started');
    });
  }
}

// Initialize and run the server
const server = new PersonalAssistantMCPServer();
server.run().catch(console.error);