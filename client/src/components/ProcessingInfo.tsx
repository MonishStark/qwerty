/** @format */

import React, { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";

interface ProcessingInfoProps {
	trackId: number;
	onComplete: () => void;
	onCancel: () => void;
}

interface ProcessingState {
	progress: number;
	status: string;
	steps: {
		text: string;
		status: "completed" | "current" | "pending";
	}[];
}

const ProcessingInfo: React.FC<ProcessingInfoProps> = ({
	trackId,
	onComplete,
	onCancel,
}) => {
	const [isRegeneration, setIsRegeneration] = useState(false);
	const [processingState, setProcessingState] = useState<ProcessingState>({
		progress: 0,
		status: "Initializing...",
		steps: [
			{
				text: isRegeneration
					? "Re-analyzing audio structure"
					: "Analyzing audio file structure",
				status: "current",
			},
			{ text: "Detecting tempo and beats", status: "pending" },
			{
				text: isRegeneration
					? "Re-separating audio components"
					: "Separating audio components",
				status: "pending",
			},
			{
				text: isRegeneration
					? "Re-creating extended sections"
					: "Creating extended sections",
				status: "pending",
			},
			{
				text: isRegeneration
					? "Finalizing new mix version"
					: "Finalizing extended mix",
				status: "pending",
			},
		],
	});

	// Check if this is a regeneration when component mounts
	useEffect(() => {
		const checkTrackStatus = async () => {
			const response = await fetch(`/api/tracks/${trackId}`);
			const track = await response.json();
			setIsRegeneration(track.extendedPaths?.length > 0);
		};
		checkTrackStatus();
	}, [trackId]);

	const { toast } = useToast();

	// Simulated progress based on polling the actual status
	useEffect(() => {
		let intervalId: number;
		let checkCount = 0;
		const maxChecks = 120; // Maximum number of status checks to prevent infinite polling

		const checkStatus = async () => {
			try {
				const response = await fetch(`/api/tracks/${trackId}/status`);

				if (!response.ok) {
					throw new Error("Failed to fetch processing status");
				}

				const data = await response.json();
				checkCount++;

				// Simple state machine to update UI based on current processing stage
				if (data.status === "processing" || data.status === "regenerate") {
					const isRegeneration = data.status === "regenerate";
					// Simulate progress based on check count as a percentage of expected total
					const progressIncrement = 100 / (maxChecks * 0.8); // Target 80% of progress through polling
					const newProgress = Math.min(80, checkCount * progressIncrement);

					// Update step status based on progress
					let newSteps = [...processingState.steps];
					let stepStatus = "Analyzing audio...";

					if (newProgress < 20) {
						newSteps[0].status = "current";
						stepStatus = "Analyzing audio file structure...";
					} else if (newProgress < 40) {
						newSteps[0].status = "completed";
						newSteps[1].status = "current";
						stepStatus = "Detecting tempo and beats...";
					} else if (newProgress < 60) {
						newSteps[0].status = "completed";
						newSteps[1].status = "completed";
						newSteps[2].status = "current";
						stepStatus = "Separating audio components...";
					} else if (newProgress < 80) {
						newSteps[0].status = "completed";
						newSteps[1].status = "completed";
						newSteps[2].status = "completed";
						newSteps[3].status = "current";
						stepStatus = "Creating extended sections...";
					}

					setProcessingState({
						progress: newProgress,
						status: stepStatus,
						steps: newSteps,
					});
				} else if (data.status === "completed") {
					setProcessingState((prev) => ({
						...prev,
						progress: 100,
						status: "Complete",
						steps: prev.steps.map((step) => ({ ...step, status: "completed" })),
					}));
					clearInterval(intervalId);
					onComplete();

					toast({
						title: "Processing Complete",
						description: "Your extended mix is ready!",
						variant: "default",
					});
				} else if (data.status === "error") {
					// Processing failed
					clearInterval(intervalId);

					toast({
						title: "Processing Failed",
						description: "There was an error processing your track.",
						variant: "destructive",
					});

					onCancel();
				}

				// Stop polling after max checks to prevent infinite polling
				if (checkCount >= maxChecks) {
					clearInterval(intervalId);
					toast({
						title: "Processing Timeout",
						description:
							"Processing is taking longer than expected. Please try again.",
						variant: "destructive",
					});
					onCancel();
				}
			} catch (error) {
				console.error("Error checking processing status:", error);
			}
		};

		// Check status immediately and then every 3 seconds
		checkStatus();
		intervalId = window.setInterval(checkStatus, 3000);

		return () => {
			if (intervalId) {
				clearInterval(intervalId);
			}
		};
	}, [trackId, onComplete, onCancel, toast]);

	const handleCancelProcessing = async () => {
		// In a real app, we would make an API call to cancel processing
		// Since our backend doesn't support cancellation yet, we'll just update the UI
		onCancel();

		toast({
			title: "Processing Cancelled",
			description: "The processing has been cancelled.",
			variant: "default",
		});
	};

	// Render step icon based on its status
	const renderStepIcon = (status: string) => {
		switch (status) {
			case "completed":
				return (
					<span className='material-icons text-success mr-2 text-sm'>
						check_circle
					</span>
				);
			case "current":
				return (
					<span className='material-icons text-primary mr-2 text-sm'>
						radio_button_checked
					</span>
				);
			default:
				return (
					<span className='material-icons mr-2 text-sm text-gray-400'>
						radio_button_unchecked
					</span>
				);
		}
	};

	return (
		<div className='bg-white rounded-xl shadow-md p-6'>
			<h2 className='text-xl font-semibold mb-4'>Processing Track</h2>

			<div className='space-y-4'>
				<div>
					<div className='flex justify-between text-sm mb-1'>
						<span className='font-medium'>{processingState.status}</span>
						<span className='text-primary'>
							{Math.round(processingState.progress)}%
						</span>
					</div>
					<div className='player-progress h-2 bg-gray-200 rounded-full overflow-hidden'>
						<div
							className='h-full bg-gradient-to-r from-primary to-purple-600 rounded-full'
							style={{ width: `${processingState.progress}%` }}></div>
					</div>
				</div>

				<div className='border border-gray-200 rounded-md p-3 bg-gray-50'>
					<h4 className='font-medium text-sm mb-2'>Processing Steps:</h4>
					<ul className='space-y-2 text-sm'>
						{processingState.steps.map((step, index) => (
							<li
								key={`step-${step.text}-${index}`}
								className='flex items-center'>
								{renderStepIcon(step.status)}
								<span
									className={step.status === "pending" ? "text-gray-400" : ""}>
									{step.text}
								</span>
							</li>
						))}
					</ul>
				</div>

				<div className='text-xs text-gray-500'>
					<p>
						This may take several minutes depending on file size and complexity
					</p>
				</div>
			</div>

			<button
				className='mt-6 w-full border border-gray-300 text-gray-700 py-2 px-4 rounded-md font-medium shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500'
				onClick={handleCancelProcessing}>
				Cancel Processing
			</button>
		</div>
	);
};

export default ProcessingInfo;
