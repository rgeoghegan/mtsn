SETS = FileList["src/set*"].map { |e| e.pathmap("%n") }
TEST_PACKAGES = FileList["src/**/*_test.go"].map { |e|
	name = e.pathmap("%n")
	name[0,name.length - 5]
}

LIBS = ["mtsn", "sha1hacks"]
LIB_FILES = FileList[LIBS.map{|n| "src/#{n}/*.go"}]

def go(args)
	ENV['GOPATH'] = Dir.pwd
	sh "go #{args}"
end

desc "Build all the executables"
task :build

desc "Run all the executables"
task :run

task :default => :run

task :test do
	TEST_PACKAGES.each do |n|
		go "test #{n}"
	end
end

task :test_v do
	TEST_PACKAGES.each do |n|
		go "test -v #{n}"
	end
end

desc "Try code in play.go"
task :play do
	go "run src/play.go"
end

desc "Clean up any built binaries"
task :clean

SETS.each do |n|
	file n => FileList["src/#{n}/**/*.go"] do
		go "build #{n}"
	end
	file n => LIB_FILES
	task :build => n
	run_set = "run#{n}".to_sym

	desc "Run set ##{n}"
	task run_set => [:build] do
		sh "./#{n}"
	end
	task :run => run_set

	task :clean do
		rm n
	end
end