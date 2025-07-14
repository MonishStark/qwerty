import React from "react";
import { Link } from "wouter";

interface AppHeaderProps {
  title: string;
}

const AppHeader: React.FC<AppHeaderProps> = ({ title }) => {
  return (
    <header className="bg-gradient-to-r from-primary to-purple-600 text-white shadow-md">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <div className="flex items-center">
          <span className="material-icons text-3xl mr-2">equalizer</span>
          <Link href="/">
            <h1 className="text-2xl font-bold cursor-pointer">{title}</h1>
          </Link>
        </div>
        <div>
          <span className="hidden md:inline-block bg-white/10 px-3 py-1 rounded-full text-sm font-medium">
            AI-Powered Extended Mix Creator
          </span>
        </div>
      </div>
    </header>
  );
};

export default AppHeader;
