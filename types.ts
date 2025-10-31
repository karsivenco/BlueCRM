import z from "zod";
import type { MochaUser } from '@getmocha/users-service/shared';

// Extended MochaUser type with local user data
export interface ExtendedMochaUser extends MochaUser {
  localUser?: {
    id: number;
    role: 'manager' | 'agent';
    full_name: string;
    phone: string | null;
    profile_picture: string | null;
    is_active: boolean;
  };
}

// User and Agent types
export const UserSchema = z.object({
  id: z.number(),
  mocha_user_id: z.string(),
  email: z.string(),
  full_name: z.string(),
  role: z.enum(['manager', 'agent']),
  phone: z.string().nullable(),
  profile_picture: z.string().nullable(),
  is_active: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type User = z.infer<typeof UserSchema>;

// Contact types
export const ContactSchema = z.object({
  id: z.number(),
  name: z.string(),
  phone: z.string(),
  email: z.string().nullable(),
  company: z.string().nullable(),
  tags: z.string().nullable(),
  notes: z.string().nullable(),
  last_contact_at: z.string().nullable(),
  created_by_user_id: z.number().nullable(),
  assigned_agent_id: z.number().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const CreateContactSchema = z.object({
  name: z.string().min(1, "Name is required"),
  phone: z.string().min(1, "Phone is required"),
  email: z.string().email().optional().or(z.literal("")),
  company: z.string().optional(),
  tags: z.string().optional(),
  notes: z.string().optional(),
});

export type Contact = z.infer<typeof ContactSchema>;
export type CreateContact = z.infer<typeof CreateContactSchema>;

// Conversation types
export const ConversationSchema = z.object({
  id: z.number(),
  contact_id: z.number(),
  assigned_agent_id: z.number().nullable(),
  status: z.enum(['active', 'closed', 'pending']),
  last_message_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type Conversation = z.infer<typeof ConversationSchema>;

// Message types
export const MessageSchema = z.object({
  id: z.number(),
  conversation_id: z.number(),
  sender_type: z.enum(['agent', 'contact']),
  sender_id: z.number().nullable(),
  content: z.string(),
  message_type: z.enum(['text', 'image', 'audio', 'document']),
  whatsapp_message_id: z.string().nullable(),
  is_read: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type Message = z.infer<typeof MessageSchema>;

// Dashboard metrics types
export interface DashboardMetrics {
  totalContacts: number;
  activeConversations: number;
  totalMessages: number;
  agentStats?: {
    id: number;
    full_name: string;
    totalContacts: number;
    activeConversations: number;
    totalMessages: number;
  }[];
}
