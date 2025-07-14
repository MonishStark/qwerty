/** @format */

import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import {
	users,
	audioTracks,
	type User,
	type InsertUser,
	type AudioTrack,
	type InsertAudioTrack,
	type UpdateAudioTrack,
} from "@shared/schema";
import { eq } from "drizzle-orm";

// Ensure DATABASE_URL is defined
if (!process.env.DATABASE_URL) {
	throw new Error("DATABASE_URL environment variable is not defined");
}

const pool = new Pool({
	connectionString: process.env.DATABASE_URL,
});

const db = drizzle(pool);

export interface IStorage {
	getUser(id: number): Promise<User | undefined>;
	getUserByUsername(username: string): Promise<User | undefined>;
	createUser(user: InsertUser): Promise<User>;
	getAudioTrack(id: number): Promise<AudioTrack | undefined>;
	createAudioTrack(track: InsertAudioTrack): Promise<AudioTrack>;
	updateAudioTrack(
		id: number,
		update: UpdateAudioTrack
	): Promise<AudioTrack | undefined>;
	getAudioTracksByUserId(userId: number): Promise<AudioTrack[]>;
}

export class PostgresStorage implements IStorage {
	async getUser(id: number): Promise<User | undefined> {
		const result = await db.select().from(users).where(eq(users.id, id));
		return result[0];
	}

	async getUserByUsername(username: string): Promise<User | undefined> {
		const result = await db
			.select()
			.from(users)
			.where(eq(users.username, username));
		return result[0];
	}

	async createUser(insertUser: InsertUser): Promise<User> {
		const result = await db.insert(users).values(insertUser).returning();
		return result[0];
	}

	async getAudioTrack(id: number): Promise<AudioTrack | undefined> {
		const result = await db
			.select()
			.from(audioTracks)
			.where(eq(audioTracks.id, id));
		return result[0];
	}

	async createAudioTrack(track: InsertAudioTrack): Promise<AudioTrack> {
		const result = await db.insert(audioTracks).values(track).returning();
		return result[0];
	}

	async updateAudioTrack(
		id: number,
		update: UpdateAudioTrack
	): Promise<AudioTrack | undefined> {
		const result = await db
			.update(audioTracks)
			.set(update)
			.where(eq(audioTracks.id, id))
			.returning();
		return result[0];
	}

	async getAudioTracksByUserId(userId: number): Promise<AudioTrack[]> {
		return db.select().from(audioTracks).where(eq(audioTracks.userId, userId));
	}

	async deleteAllUserTracks(userId: number): Promise<void> {
		await db.delete(audioTracks).where(eq(audioTracks.userId, userId));
	}
}

export const storage = new PostgresStorage();
