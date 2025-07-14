/** @format */

import React, { useState, useRef } from "react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface UploadSectionProps {
	onUploadSuccess: (trackId: number) => void;
}

const UploadSection: React.FC<UploadSectionProps> = ({ onUploadSuccess }) => {
	const [isDragActive, setIsDragActive] = useState(false);
	const [isUploading, setIsUploading] = useState(false);
	const fileInputRef = useRef<HTMLInputElement>(null);
	const { toast } = useToast();

	const handleUploadClick = () => {
		if (fileInputRef.current) {
			fileInputRef.current.click();
		}
	};

	const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
		e.preventDefault();
		setIsDragActive(true);
	};

	const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
		e.preventDefault();
		setIsDragActive(false);
	};

	const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
		e.preventDefault();
		setIsDragActive(false);

		if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
			handleFileUpload(e.dataTransfer.files[0]);
		}
	};

	const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		if (e.target.files && e.target.files.length > 0) {
			handleFileUpload(e.target.files[0]);
		}
	};

	const handleFileUpload = async (file: File) => {
		// Check file type
		const allowedTypes = [
			"audio/mpeg",
			"audio/wav",
			"audio/flac",
			"audio/aiff",
			"audio/x-aiff",
		];
		if (!allowedTypes.includes(file.type)) {
			toast({
				title: "Invalid file type",
				description: "Please upload an MP3, WAV, FLAC, or AIFF file.",
				variant: "destructive",
			});
			return;
		}

		setIsUploading(true);

		try {
			const formData = new FormData();
			formData.append("audio", file);

			const response = await fetch("/api/tracks/upload", {
				method: "POST",
				body: formData,
			});

			if (!response.ok) {
				throw new Error(
					`Upload failed: ${response.status} ${response.statusText}`
				);
			}

			const data = await response.json();
			toast({
				title: "Upload successful",
				description: "Your track has been uploaded successfully.",
			});

			onUploadSuccess(data.id);
		} catch (error) {
			console.error("Upload error:", error);
			toast({
				title: "Upload failed",
				description:
					error.message || "An unexpected error occurred during upload.",
				variant: "destructive",
			});
		} finally {
			setIsUploading(false);
			if (fileInputRef.current) {
				fileInputRef.current.value = "";
			}
		}
	};

	return (
		<div className='bg-white rounded-xl shadow-md p-6'>
			<h2 className='text-xl font-semibold mb-4'>Upload Track</h2>

			<div
				className={`drop-zone p-8 flex flex-col items-center justify-center text-center cursor-pointer ${
					isDragActive ? "active" : ""
				} ${isUploading ? "opacity-50 pointer-events-none" : ""}`}
				onClick={handleUploadClick}
				onDragOver={handleDragOver}
				onDragLeave={handleDragLeave}
				onDrop={handleDrop}>
				{isUploading ? (
					<>
						<span className='material-icons text-5xl text-primary-light mb-4 animate-pulse'>
							cloud_upload
						</span>
						<p className='font-medium mb-2'>Uploading...</p>
					</>
				) : (
					<>
						<span className='material-icons text-5xl text-primary-light mb-4'>
							cloud_upload
						</span>
						<p className='font-medium mb-2'>Drag & drop your track here</p>
						<p className='text-sm text-gray-500 mb-4'>or click to browse</p>
						<p className='text-xs text-gray-400'>
							Supports MP3, WAV, FLAC, AIFF
						</p>
					</>
				)}

				<input
					type='file'
					id='file-upload'
					className='hidden'
					accept='.mp3,.wav,.flac,.aiff,audio/mpeg,audio/wav,audio/flac,audio/aiff,audio/x-aiff'
					ref={fileInputRef}
					onChange={handleFileChange}
					disabled={isUploading}
				/>
			</div>
		</div>
	);
};

export default UploadSection;
