char toto()
{
    char buffer[4096];
    buffer[0] = 0;
    toto();
    return buffer[0] + buffer[sizeof(buffer)-1];
}

int main()
{
    char c = toto();
    return c;
}
