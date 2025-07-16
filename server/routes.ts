/** @format */

import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import {
	processingSettingsSchema,
	updateAudioTrackSchema,
} from "@shared/schema";
import multer from "multer";
import path from "path";
import fs from "fs";
import { PythonShell } from "python-shell";

// Setup multer for file uploads with proper validation
const uploadsDir =
	process.env.UPLOADS_DIR || path.join(process.cwd(), "uploads");
const resultDir =
	process.env.RESULTS_DIR || path.join(process.cwd(), "results");

// Security: Validate environment variables to prevent malicious paths
if (
	process.env.UPLOADS_DIR &&
	(process.env.UPLOADS_DIR.includes("..") ||
		process.env.UPLOADS_DIR.includes("~"))
) {
	throw new Error("Invalid UPLOADS_DIR: Path traversal attempts detected");
}
if (
	process.env.RESULTS_DIR &&
	(process.env.RESULTS_DIR.includes("..") ||
		process.env.RESULTS_DIR.includes("~"))
) {
	throw new Error("Invalid RESULTS_DIR: Path traversal attempts detected");
}

// Ensure directories exist and are properly secured
if (!fs.existsSync(uploadsDir)) {
	fs.mkdirSync(uploadsDir, { recursive: true });
}
if (!fs.existsSync(resultDir)) {
	fs.mkdirSync(resultDir, { recursive: true });
}

// Security: Normalize and validate directory paths to prevent path traversal
const normalizedUploadsDir = path.resolve(uploadsDir);
const normalizedResultDir = path.resolve(resultDir);

// Security utility function to validate file paths and prevent path traversal
function validateFilePath(filePath: string, allowedDirectory: string): boolean {
	try {
		// Normalize the file path to resolve any relative path components
		const normalizedPath = path.resolve(filePath);
		const normalizedAllowedDir = path.resolve(allowedDirectory);

		// Check if the normalized path starts with the allowed directory
		// This prevents path traversal attacks like "../../../etc/passwd"
		const isWithinAllowedDir =
			normalizedPath.startsWith(normalizedAllowedDir + path.sep) ||
			normalizedPath === normalizedAllowedDir;

		// Additional security checks
		const containsDangerousPatterns =
			filePath.includes("..") ||
			filePath.includes("~") ||
			filePath.includes("\0") || // null byte
			filePath.includes("%00"); // URL encoded null byte

		return isWithinAllowedDir && !containsDangerousPatterns;
	} catch (error) {
		// If there's any error in path resolution, reject the path
		return false;
	}
}

// Security function to sanitize filename
function sanitizeFilename(filename: string): string {
	// Remove dangerous characters and path traversal attempts
	return filename
		.replace(/[<>:"/\\|?*\0]/g, "") // Remove filesystem-dangerous characters
		.replace(/\.\./g, "") // Remove path traversal attempts
		.replace(/^\.+/, "") // Remove leading dots
		.slice(0, 255); // Limit filename length
}
const storage_config = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, normalizedUploadsDir);
	},
	filename: function (req, file, cb) {
		const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
		const sanitizedOriginalName = sanitizeFilename(file.originalname);
		const extension = path.extname(sanitizedOriginalName);
		cb(null, uniqueSuffix + extension);
	},
});

const upload = multer({
	storage: storage_config,
	limits: {
		fileSize: 15 * 1024 * 1024,
	},
	fileFilter: (req, file, cb) => {
		const allowedMimeTypes = [
			"audio/mpeg",
			"audio/wav",
			"audio/flac",
			"audio/aiff",
			"audio/x-aiff",
		];
		if (allowedMimeTypes.includes(file.mimetype)) {
			cb(null, true);
		} else {
			cb(
				new Error(
					"Invalid file type. Only MP3, WAV, FLAC, and AIFF files are allowed."
				)
			);
		}
	},
});

export async function registerRoutes(app: Express): Promise<Server> {
	const httpServer = createServer(app);

	// Set up user for demo purposes
	let demoUser = await storage.getUserByUsername("demo");
	if (!demoUser) {
		demoUser = await storage.createUser({
			username: "demo",
			password: "password", // In a real app, this would be hashed
		});
	}

	/**
	 * Route Handlers Documentation
	 *
	 * POST /api/tracks/upload
	 * - Handles audio file upload
	 * - Creates track entry in database
	 * - Analyzes audio for basic info (format, tempo, key)
	 *
	 * GET /api/tracks/:id
	 * - Retrieves specific track information
	 *
	 * GET /api/tracks
	 * - Lists all tracks for demo user
	 *
	 * DELETE /api/tracks
	 * - Clears all tracks and associated files
	 *
	 * POST /api/tracks/:id/process
	 * - Processes track to create extended version
	 * - Handles versioning and status updates
	 *
	 * GET /api/tracks/:id/status
	 * - Returns current processing status
	 *
	 * GET /api/audio/:id/:type
	 * - Streams audio files (original or extended)
	 *
	 * GET /api/tracks/:id/download
	 * - Handles download of processed tracks
	 */

	// Upload audio file
	app.post(
		"/api/tracks/upload",
		upload.single("audio"),
		async (req: Request, res: Response) => {
			try {
				if (!req.file) {
					return res.status(400).json({ message: "No file uploaded" });
				}

				// Security: Validate uploaded file path
				if (!validateFilePath(req.file.path, normalizedUploadsDir)) {
					// Clean up the invalid file
					if (fs.existsSync(req.file.path)) {
						fs.unlinkSync(req.file.path);
					}
					return res
						.status(403)
						.json({ message: "Access denied: Invalid file path" });
				}

				const track = await storage.createAudioTrack({
					originalFilename: req.file.originalname,
					originalPath: req.file.path,
					userId: demoUser.id, // Using demo user for now
				});

				// Get basic audio info using Python
				const options = {
					mode: "text" as const,
					pythonPath: process.platform === "win32" ? "python" : "python3",
					pythonOptions: ["-u"],
					scriptPath: path.join(process.cwd(), "server"),
					args: [req.file.path],
				};

				PythonShell.run("utils.py", options)
					.then(async (results) => {
						if (results && results.length > 0) {
							try {
								const audioInfo = JSON.parse(results[0]);
								await storage.updateAudioTrack(track.id, {
									format: audioInfo.format,
									bitrate: audioInfo.bitrate || null,
									duration: audioInfo.duration || null,
									bpm: audioInfo.bpm || null,
									key: audioInfo.key || null,
								});
							} catch (e) {
								console.error("Error parsing audio info:", e);
							}
						}
					})
					.catch((err) => {
						console.error("Error analyzing audio:", err);
					});

				return res.status(201).json(track);
			} catch (error) {
				console.error("Upload error:", error);
				return res
					.status(500)
					.json({ message: "Error uploading file", error: error.message });
			}
		}
	);

	// Get a specific track
	app.get("/api/tracks/:id", async (req: Request, res: Response) => {
		try {
			const id = parseInt(req.params.id, 10);
			if (isNaN(id)) {
				return res.status(400).json({ message: "Invalid track ID" });
			}

			const track = await storage.getAudioTrack(id);
			if (!track) {
				return res.status(404).json({ message: "Track not found" });
			}

			return res.json(track);
		} catch (error) {
			console.error("Get track error:", error);
			return res
				.status(500)
				.json({ message: "Error retrieving track", error: error.message });
		}
	});

	// Get all tracks for the demo user
	app.get("/api/tracks", async (req: Request, res: Response) => {
		try {
			const tracks = await storage.getAudioTracksByUserId(demoUser.id);
			return res.json(tracks);
		} catch (error) {
			console.error("Get tracks error:", error);
			return res
				.status(500)
				.json({ message: "Error retrieving tracks", error: error.message });
		}
	});

	// Clear all tracks
	app.delete("/api/tracks", async (req: Request, res: Response) => {
		try {
			const tracks = await storage.getAudioTracksByUserId(demoUser.id);

			// Delete files with security validation
			for (const track of tracks) {
				// Validate and delete original file
				if (
					track.originalPath &&
					validateFilePath(track.originalPath, normalizedUploadsDir)
				) {
					if (fs.existsSync(track.originalPath)) {
						fs.unlinkSync(track.originalPath);
					}
				}

				// Validate and delete extended files
				if (track.extendedPaths && Array.isArray(track.extendedPaths)) {
					for (const filePath of track.extendedPaths) {
						if (validateFilePath(filePath, normalizedResultDir)) {
							if (fs.existsSync(filePath)) {
								fs.unlinkSync(filePath);
							}
						}
					}
				}
			}

			// Delete from database
			await storage.deleteAllUserTracks(demoUser.id);

			return res.json({ message: "All tracks cleared" });
		} catch (error) {
			console.error("Clear tracks error:", error);
			return res
				.status(500)
				.json({ message: "Error clearing tracks", error: error.message });
		}
	});

	// Process a track to create extended version
	app.post("/api/tracks/:id/process", async (req: Request, res: Response) => {
		try {
			const id = parseInt(req.params.id, 10);
			if (isNaN(id)) {
				return res.status(400).json({ message: "Invalid track ID" });
			}

			const track = await storage.getAudioTrack(id);
			if (!track) {
				return res.status(404).json({ message: "Track not found" });
			}

			// Check version limit

			if (track.versionCount > 3) {
				return res.status(400).json({
					message: "Maximum version limit (3) reached",
				});
			}

			// Validate settings from request
			const settings = processingSettingsSchema.parse(req.body);

			// Update track status and settings
			await storage.updateAudioTrack(id, {
				status: track.extendedPaths?.length ? "regenerate" : "processing",
				settings: settings,
			});

			// Generate a filename for the extended version
			const outputBase = path.basename(
				track.originalFilename,
				path.extname(track.originalFilename)
			);
			const fileExt = path.extname(track.originalFilename);
			const version = track.extendedPaths?.length || 0;
			const outputPath = path.join(
				normalizedResultDir,
				`${sanitizeFilename(outputBase)}_extended_v${version + 1}${fileExt}`
			);

			// Execute the Python script for audio processing
			const options = {
				mode: "text" as const,
				pythonPath: process.platform === "win32" ? "python" : "python3",
				pythonOptions: ["-u"],
				scriptPath: path.join(process.cwd(), "server"),
				args: [
					track.originalPath,
					outputPath,
					settings.introLength.toString(),
					settings.outroLength.toString(),
					settings.preserveVocals.toString(),
					settings.beatDetection,
				],
			};

			// Send initial response
			res.status(202).json({
				message: "Processing started",
				trackId: id,
				status: "processing",
			});

			// Start processing in background
			PythonShell.run("audioProcessor.py", options)
				.then(async (results) => {
					console.log("Processing complete:", results);

					// Get audio info of the processed file
					const audioInfoOptions = {
						mode: "text" as const,
						pythonPath: process.platform === "win32" ? "python" : "python3",
						pythonOptions: ["-u"],
						scriptPath: path.join(process.cwd(), "server"),
						args: [outputPath],
					};

					return PythonShell.run("utils.py", audioInfoOptions).then(
						async (infoResults) => {
							let extendedDuration = null;

							if (infoResults && infoResults.length > 0) {
								try {
									const audioInfo = JSON.parse(infoResults[0]);
									console.log("Extended audio info:", audioInfo);
									extendedDuration = audioInfo.duration || null;
								} catch (e) {
									console.error("Error parsing extended audio info:", e);
								}
							}

							// Update track with completed status and add new version
							const track = await storage.getAudioTrack(id);
							const currentPaths = track?.extendedPaths || [];
							const currentDurations = track?.extendedDurations || [];
							let extendedPaths = [...currentPaths, outputPath];
							console.log("extendedPaths:", extendedPaths);

							return storage.updateAudioTrack(id, {
								status: "completed",
								extendedPaths: extendedPaths,
								extendedDurations: [...currentDurations, extendedDuration],
								versionCount: (track.versionCount || 1) + 1,
							});
						}
					);
				})
				.catch(async (error) => {
					console.error("Processing error:", error);
					await storage.updateAudioTrack(id, {
						status: "error",
					});
				});
		} catch (error) {
			console.error("Process track error:", error);
			return res
				.status(500)
				.json({ message: "Error processing track", error: error.message });
		}
	});

	// Get processing status
	app.get("/api/tracks/:id/status", async (req: Request, res: Response) => {
		try {
			const id = parseInt(req.params.id, 10);
			if (isNaN(id)) {
				return res.status(400).json({ message: "Invalid track ID" });
			}

			const track = await storage.getAudioTrack(id);
			if (!track) {
				return res.status(404).json({ message: "Track not found" });
			}

			return res.json({ status: track.status });
		} catch (error) {
			console.error("Get status error:", error);
			return res
				.status(500)
				.json({ message: "Error retrieving status", error: error.message });
		}
	});

	// Serve audio files
	app.get("/api/audio/:id/:type", async (req: Request, res: Response) => {
		try {
			const id = parseInt(req.params.id, 10);
			if (isNaN(id)) {
				return res.status(400).json({ message: "Invalid track ID" });
			}

			const type = req.params.type;
			if (type !== "original" && type !== "extended") {
				return res.status(400).json({ message: "Invalid audio type" });
			}

			const track = await storage.getAudioTrack(id);
			if (!track) {
				return res.status(404).json({ message: "Track not found" });
			}

			let filePath = track.originalPath;
			if (type === "extended") {
				const version = parseInt(req.query.version as string) || 0;
				const extendedPaths = Array.isArray(track.extendedPaths)
					? track.extendedPaths
					: [];
				filePath = extendedPaths[version];
			}

			if (!filePath) {
				return res
					.status(404)
					.json({ message: `${type} audio file not found` });
			}

			// Security: Validate file path contains only safe characters and extensions
			const allowedExtensions = [".mp3", ".wav", ".flac", ".aiff"];
			const fileExtension = path.extname(filePath).toLowerCase();
			if (!allowedExtensions.includes(fileExtension)) {
				return res.status(400).json({ message: "Invalid file type" });
			}

			// Security: Validate file path to prevent path traversal
			const isUploadFile = validateFilePath(filePath, normalizedUploadsDir);
			const isResultFile = validateFilePath(filePath, normalizedResultDir);

			if (!isUploadFile && !isResultFile) {
				return res
					.status(403)
					.json({ message: "Access denied: Invalid file path" });
			}

			if (!fs.existsSync(filePath)) {
				return res
					.status(404)
					.json({ message: "Audio file not found on disk" });
			}

			const stat = fs.statSync(filePath);
			const fileSize = stat.size;
			const range = req.headers.range;

			if (range) {
				const parts = range.replace(/bytes=/, "").split("-");
				const start = parseInt(parts[0], 10);
				const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
				const chunksize = end - start + 1;
				const file = fs.createReadStream(filePath, { start, end });
				const head = {
					"Content-Range": `bytes ${start}-${end}/${fileSize}`,
					"Accept-Ranges": "bytes",
					"Content-Length": chunksize,
					"Content-Type": "audio/mpeg",
				};
				res.writeHead(206, head);
				file.pipe(res);
			} else {
				const head = {
					"Content-Length": fileSize,
					"Content-Type": "audio/mpeg",
				};
				res.writeHead(200, head);
				fs.createReadStream(filePath).pipe(res);
			}
		} catch (error) {
			console.error("Stream audio error:", error);
			return res.status(500).json({
				message: "Error streaming audio",
				error: error instanceof Error ? error.message : "Unknown error",
			});
		}
	});

	// Download extended audio
	app.get("/api/tracks/:id/download", async (req: Request, res: Response) => {
		try {
			const id = parseInt(req.params.id, 10);
			if (isNaN(id)) {
				return res.status(400).json({ message: "Invalid track ID" });
			}

			const track = await storage.getAudioTrack(id);
			if (!track) {
				return res.status(404).json({ message: "Track not found" });
			}

			const version = parseInt(req.query.version as string) || 0;
			const extendedPaths = Array.isArray(track.extendedPaths)
				? track.extendedPaths
				: [];

			if (version >= extendedPaths.length || !extendedPaths[version]) {
				return res.status(404).json({ message: "Extended version not found" });
			}

			const filePath = extendedPaths[version];

			// Security: Validate file path contains only safe characters and extensions
			const allowedExtensions = [".mp3", ".wav", ".flac", ".aiff"];
			const fileExtension = path.extname(filePath).toLowerCase();
			if (!allowedExtensions.includes(fileExtension)) {
				return res.status(400).json({ message: "Invalid file type" });
			}

			// Security: Validate file path to prevent path traversal
			if (!validateFilePath(filePath, normalizedResultDir)) {
				return res
					.status(403)
					.json({ message: "Access denied: Invalid file path" });
			}

			if (!fs.existsSync(filePath)) {
				return res
					.status(404)
					.json({ message: "Extended audio file not found on disk" });
			}

			// Extract original filename without extension
			const originalNameWithoutExt = path.basename(
				track.originalFilename,
				path.extname(track.originalFilename)
			);

			// Create download filename with version number
			const downloadFilename = `${originalNameWithoutExt}_extended_v${
				version + 1
			}${path.extname(track.originalFilename)}`;

			res.download(filePath, downloadFilename);
		} catch (error) {
			console.error("Download error:", error);
			return res.status(500).json({
				message: "Error downloading file",
				error: error instanceof Error ? error.message : "Unknown error",
			});
		}
	});

	return httpServer;
}
