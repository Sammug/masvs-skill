- (void)run:(NSString *)token {
    [[NSUserDefaults standardUserDefaults] setObject:token forKey:@"auth_token"];
    NSLog(@"token %@", token);
}
