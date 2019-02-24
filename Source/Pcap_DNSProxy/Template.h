// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


#ifndef PCAP_DNSPROXY_TEMPLATE_H
#define PCAP_DNSPROXY_TEMPLATE_H

#include "Class.h"

//////////////////////////////////////////////////
// Template definition
// 
template<typename Ty, typename Container = std::queue<Ty>> class BlockingQueue
{
public:
	using ContainerType = Container;
	using ValueType = typename Container::value_type;
	using Reference = typename Container::reference;
	using ConstReference = typename Container::const_reference;
	using SizeType = typename Container::size_type;
	using MutexType = std::mutex;
	using ConditionVariableType = std::condition_variable;

private:
	Container                OriginalQueue;
	MutexType                OriginalMutex;
	ConditionVariableType    OriginalConditionVariable;

public:
//Redefine operator function
	BlockingQueue() = default;
	BlockingQueue(const BlockingQueue &) = delete;
	BlockingQueue & operator=(const BlockingQueue &) = delete;

//Pop function
	void pop(
		Reference Element)
	{
		std::unique_lock<MutexType> Lock(OriginalMutex);
		OriginalConditionVariable.wait(Lock, [this](){return !OriginalQueue.empty();});
		Element = std::move(OriginalQueue.front());
		OriginalQueue.pop();

		return;
	}

//Try to pop function
	bool try_pop(
		Reference Element)
	{
		std::lock_guard<MutexType> Lock(OriginalMutex);
		if (OriginalQueue.empty())
			return false;
		Element = std::move(OriginalQueue.front());
		OriginalQueue.pop();

		return true;
	}

//Empty check function
	bool empty(
		void) const
	{
		std::lock_guard<MutexType> Lock(OriginalMutex);
		return OriginalQueue.empty();
	}

//Size return function
	SizeType size(
		void) const
	{
		std::lock_guard<MutexType> Lock(OriginalMutex);
		return OriginalQueue.size();
	}

//Push function
	void push(
		const ValueType &Element)
	{
		std::unique_lock<MutexType> Lock(OriginalMutex);
		OriginalQueue.push(Element);
		Lock.unlock();
		OriginalConditionVariable.notify_one();

		return;
	}

//Push function
	void push(
		ValueType &&Element)
	{
		std::unique_lock<MutexType> Lock(OriginalMutex);
		OriginalQueue.push(std::move(Element));
		Lock.unlock();
		OriginalConditionVariable.notify_one();

		return;
	}
};
template<typename Ty> using BLOCKING_QUEUE = BlockingQueue<Ty>;

#if defined(ENABLE_LIBSODIUM)
//DNSCryptHeapBufferTable template class
template<typename Ty> class DNSCryptHeapBufferTable
{
public:
	Ty                                   *Buffer;
	size_t                               BufferSize;

//Redefine operator functions
//	DNSCryptHeapBufferTable() = default;
	DNSCryptHeapBufferTable(const DNSCryptHeapBufferTable &) = delete;
	DNSCryptHeapBufferTable & operator=(const DNSCryptHeapBufferTable &) = delete;

//Member functions
	DNSCryptHeapBufferTable(
		void);
	explicit DNSCryptHeapBufferTable(
		const size_t Size);
	DNSCryptHeapBufferTable(
		const size_t Count, 
		const size_t Size);
	void Swap(
		DNSCryptHeapBufferTable &Other);
	~DNSCryptHeapBufferTable(
		void);
};
template<typename Ty> using DNSCRYPT_HEAP_BUFFER_TABLE = DNSCryptHeapBufferTable<Ty>;

//Template functions
//DNSCryptHeapBufferTable template class constructor
template<typename Ty> DNSCryptHeapBufferTable<Ty>::DNSCryptHeapBufferTable(
	void)
{
	Buffer = nullptr;
	BufferSize = 0;

	return;
}

//DNSCryptHeapBufferTable template class constructor
template<typename Ty> DNSCryptHeapBufferTable<Ty>::DNSCryptHeapBufferTable(
	const size_t Size)
{
	Buffer = reinterpret_cast<Ty *>(sodium_malloc(Size));
	if (Buffer != nullptr)
	{
		sodium_memzero(Buffer, Size);
		BufferSize = Size;
	}
	else {
		exit(EXIT_FAILURE);
	}

	return;
}

//DNSCryptHeapBufferTable template class constructor
template<typename Ty> DNSCryptHeapBufferTable<Ty>::DNSCryptHeapBufferTable(
	const size_t Count, 
	const size_t Size)
{
	Buffer = reinterpret_cast<Ty *>(sodium_allocarray(Count, Size));
	if (Buffer != nullptr)
	{
		sodium_memzero(Buffer, Count * Size);
		BufferSize = Count * Size;
	}
	else {
		exit(EXIT_FAILURE);
	}

	return;
}

//DNSCryptHeapBufferTable template class Swap function
template<typename Ty> void DNSCryptHeapBufferTable<Ty>::Swap(
	DNSCryptHeapBufferTable &Other)
{
	const auto BufferTemp = Buffer;
	Buffer = Other.Buffer;
	Other.Buffer = BufferTemp;
	const auto BufferSizeTemp = BufferSize;
	BufferSize = Other.BufferSize;
	Other.BufferSize = BufferSizeTemp;

	return;
}

//DNSCryptHeapBufferTable template class destructor
template<typename Ty> DNSCryptHeapBufferTable<Ty>::~DNSCryptHeapBufferTable(
	void)
{
	sodium_free(Buffer);
	Buffer = nullptr;
	BufferSize = 0;

	return;
}
#endif
#endif
