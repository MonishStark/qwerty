/** @format */

import React, { useState } from "react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { ProcessingSettings } from "@shared/schema";

interface SettingsPanelProps {
	trackId: number | null;
	onProcessingStart: () => void;
	disabled?: boolean;
}

const SettingsPanel: React.FC<SettingsPanelProps> = ({
	trackId,
	onProcessingStart,
	disabled = false,
}) => {
	const [settings, setSettings] = useState<ProcessingSettings>({
		introLength: 16,
		outroLength: 16,
		preserveVocals: true,
		beatDetection: "auto",
	});
	const [isSubmitting, setIsSubmitting] = useState(false);
	const { toast } = useToast();

	const incrementIntroLength = () => {
		if (settings.introLength < 64) {
			setSettings((prev) => ({
				...prev,
				introLength: prev.introLength + 8,
				outroLength: prev.outroLength + 8,
			}));
		}
	};

	const decrementIntroLength = () => {
		if (settings.introLength > 8) {
			setSettings((prev) => ({
				...prev,
				introLength: prev.introLength - 8,
				outroLength: prev.outroLength - 8,
			}));
		}
	};

	const incrementOutroLength = () => {
		if (settings.outroLength < 64) {
			setSettings((prev) => ({
				...prev,
				outroLength: prev.outroLength + 8,
			}));
		}
	};

	const decrementOutroLength = () => {
		if (settings.outroLength > 8) {
			setSettings((prev) => ({
				...prev,
				outroLength: prev.outroLength - 8,
			}));
		}
	};

	const togglePreserveVocals = () => {
		setSettings((prev) => ({
			...prev,
			preserveVocals: !prev.preserveVocals,
		}));
	};

	const handleBeatDetectionChange = (
		e: React.ChangeEvent<HTMLSelectElement>
	) => {
		setSettings((prev) => ({
			...prev,
			beatDetection: e.target.value as "auto" | "librosa" | "madmom",
		}));
	};

	const handleGenerateClick = async () => {
		if (!trackId) {
			toast({
				title: "No track selected",
				description: "Please upload a track first.",
				variant: "destructive",
			});
			return;
		}

		setIsSubmitting(true);

		try {
			const response = await fetch(`/api/tracks/${trackId}/process`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify(settings),
			});

			if (!response.ok) {
				throw new Error(
					`Failed to start processing: ${response.status} ${response.statusText}`
				);
			}

			toast({
				title: "Processing Started",
				description:
					"Your track is now being processed. This may take a few minutes.",
			});

			onProcessingStart();
		} catch (error) {
			console.error("Processing error:", error);
			toast({
				title: "Processing Failed",
				description: error.message || "An unexpected error occurred.",
				variant: "destructive",
			});
		} finally {
			setIsSubmitting(false);
		}
	};

	return (
		<div className='bg-white rounded-xl shadow-md p-6'>
			<h2 className='text-xl font-semibold mb-4'>Extension Settings</h2>

			<div className='space-y-4'>
				<div>
					<label className='block text-sm font-medium text-gray-700 mb-1'>
						Intro Length (bars)
					</label>
					<div className='flex items-center'>
						<button
							className='bg-gray-200 px-2 py-1 rounded-l-md disabled:opacity-50'
							onClick={decrementIntroLength}
							disabled={settings.introLength <= 8 || disabled}>
							<span className='material-icons text-sm'>remove</span>
						</button>
						<div className='px-4 py-1 bg-gray-100 text-center'>
							{settings.introLength}
						</div>
						<button
							className='bg-gray-200 px-2 py-1 rounded-r-md disabled:opacity-50'
							onClick={incrementIntroLength}
							disabled={settings.introLength >= 64 || disabled}>
							<span className='material-icons text-sm'>add</span>
						</button>
					</div>
				</div>
			</div>

			<button
				className='mt-6 w-full bg-gradient-to-r from-primary to-purple-600 text-white py-2 px-4 rounded-md font-medium shadow hover:shadow-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:opacity-50'
				onClick={handleGenerateClick}
				disabled={!trackId || isSubmitting || disabled}
				data-generate-button='true'>
				{isSubmitting ? "Starting Process..." : "Generate Extended Version"}
			</button>
		</div>
	);
};

export default SettingsPanel;
